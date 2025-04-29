package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultHttpClientMaxIdleCon          = 10
	defaultHttpClientIdleConnTimeout     = 30 * time.Second
	defaultHttpClientTLSHandshakeTimeout = 30 * time.Second
	defaultFetchInterval                 = 24 * time.Hour
	defaultTimeout                       = 60 * time.Second

	oidcDiscoveryPath = "/.well-known/openid-configuration"
)

type discoveryDocument struct {
	JwksURI string `json:"jwks_uri"`
}

type JWKSFetcher struct {
	jwksURL       string
	jwks          *JWKS
	mutex         *sync.RWMutex
	fetchInterval time.Duration
	httpClient    *http.Client
	logger        *slog.Logger
}

// JWKSFetcherOpts holds the confifuration for the JWKSFetcher.
type JWKSFetcherOpts struct {
	baseURL                   string
	entraIDtenant             string
	fetchInterval             time.Duration
	tlsHandshakeTimeout       time.Duration
	timeout                   time.Duration
	httpClientIdleConnTimeout time.Duration
	httpClientMaxIdleCon      int
	debugLog                  bool
}

// Option is a function that configures a JWKSFetcherOpts.
type Option func(*JWKSFetcherOpts) error

// WithBaseURL sets the base url for fetching the auth server discovery document.
// Cannot by used together with WithEntraIDTenantID.
func WithBaseURL(url string) Option {
	return func(o *JWKSFetcherOpts) error {
		if url == "" {
			return fmt.Errorf("WithBaseURL: url cannot be empty")
		}

		if o.entraIDtenant != "" {
			return fmt.Errorf("WithBaseURL: cannot set base URL when entraID tenant is specified")
		}
		o.baseURL = url
		return nil
	}
}

// WithEntraIDTenantID configures the fetcher for Entra ID using the tenant ID.
// Constructs BaseURL automatically.
// Cannot be used together with WithBaseURL.
func WithEntraIDTenantID(tenantID string) Option {
	return func(o *JWKSFetcherOpts) error {
		if tenantID == "" {
			return fmt.Errorf("WithEntraIDTenantID: tenant ID cannot be empty")
		}

		if o.baseURL != "" {
			return fmt.Errorf("WithEntraIDTenantID: cannot set tenant ID when base URL is already specified")
		}

		o.baseURL = fmt.Sprintf("https://login.microsoftonline.com/%s", tenantID)
		return nil
	}
}

// WithFetchInterval sets the interval for refreshing the JWKS.
func WithFetchInterval(d time.Duration) Option {
	return func(o *JWKSFetcherOpts) error {
		if d <= 0 {
			return fmt.Errorf("WithFetchInterval: duration must be positive")
		}
		o.fetchInterval = d
		return nil
	}
}

// WithTimeout sets the general timeout for HTTP requests made by the fetcher.
func WithTimeout(d time.Duration) Option {
	return func(o *JWKSFetcherOpts) error {
		if d <= 0 {
			return fmt.Errorf("WithTimeout: duration must be positive")
		}
		o.timeout = d
		return nil
	}
}

// WithTLSHandshakeTimeout sets the timeout for the TLS handshake.
func WithTLSHandshakeTimeout(d time.Duration) Option {
	return func(o *JWKSFetcherOpts) error {
		if d <= 0 {
			return fmt.Errorf("WithTLSHandshakeTimeout: duration must be positive")
		}
		o.tlsHandshakeTimeout = d
		return nil
	}
}

// WithHTTPClientIdleConnTimeout sets the idle connection timeout for the fetcher.
// A timeout of 0 means no timeout will occur.
func WithHTTPClientIdleConnTimeout(d time.Duration) Option {
	return func(o *JWKSFetcherOpts) error {
		if d < 0 {
			return fmt.Errorf("WithHTTPClientIdleConnTimeout: duration cannot be negative")
		}
		o.httpClientIdleConnTimeout = d
		return nil
	}
}

// WithHTTPClientMaxIdleConns sets the maximum number of idle connections for the fetcher.
func WithHTTPClientMaxIdleConns(n int) Option {
	return func(o *JWKSFetcherOpts) error {
		if n < 0 {
			return fmt.Errorf("WithHTTPClientMaxIdleConns: number cannot be negative")
		}
		o.httpClientMaxIdleCon = n
		return nil
	}
}

func NewJWKSFetcher(options ...Option) (*JWKSFetcher, error) {
	// Set default fetcher opts
	opts := &JWKSFetcherOpts{
		fetchInterval:             defaultFetchInterval,
		tlsHandshakeTimeout:       defaultHttpClientTLSHandshakeTimeout,
		timeout:                   defaultTimeout,
		httpClientIdleConnTimeout: defaultHttpClientIdleConnTimeout,
		httpClientMaxIdleCon:      defaultHttpClientMaxIdleCon,
	}

	// Apply options set by user
	for _, opt := range options {
		err := opt(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to construct JWKSFetcher: %w", err)
		}
	}

	if opts.baseURL == "" {
		return nil, fmt.Errorf("either WithBaseURL or WithEntraIDTenantID must be used")
	}

	httpClient := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        opts.httpClientMaxIdleCon,
			IdleConnTimeout:     opts.httpClientIdleConnTimeout,
			TLSHandshakeTimeout: opts.tlsHandshakeTimeout,
		},
	}
	jwksURL, err := fetchJWKSURL(context.Background(), opts.baseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS URL")
	}

	var logLevel slog.Level
	if opts.DebugLog {
		logLevel = slog.LevelDebug
	} else {
		logLevel = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	return &JWKSFetcher{
		jwksURL:       jwksURL,
		mutex:         &sync.RWMutex{},
		jwks:          nil,
		fetchInterval: opts.fetchInterval,
		httpClient:    httpClient,
		logger:        logger,
	}, nil
}

// Start synchronization of JWKS into in-memory store.
func (f *JWKSFetcher) Start(ctx context.Context) {
	f.logger.DebugContext(ctx, "starting JWKS fetcher", "interval", f.fetchInterval)
	go func() {
		ticker := time.NewTicker(f.fetchInterval)
		defer ticker.Stop()

		for {
			if err := f.synchronizeKeys(ctx); err != nil {
				f.logger.Error("failed to fetch remote keys", "error", err)
			}

			select {
			case <-ctx.Done():
				f.logger.InfoContext(ctx, "jwks sync stopped")
				return
			case <-ticker.C:
				continue
			}
		}
	}()
}

// Fetches the lastest keys and updates the in-memory store.
func (f *JWKSFetcher) synchronizeKeys(ctx context.Context) error {
	f.logger.DebugContext(ctx, "fetching new keys")

	newJWKS, err := f.fetchRemoteJWKS(ctx, f.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch remote keys: %w", err)
	}

	f.mutex.Lock()
	f.jwks = &newJWKS
	f.mutex.Unlock()

	f.logger.DebugContext(ctx, "JWKS keys refreshed successfully")

	return nil
}

// Executes the JWKS fetch request.
func (f *JWKSFetcher) fetchRemoteJWKS(ctx context.Context, jwksURL string) (JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return JWKS{}, fmt.Errorf("crafting request to %s failed with %w", jwksURL, err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return JWKS{}, fmt.Errorf("request to %s failed with %w", jwksURL, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("received non 200 status (%d) from JWKS url: %s", resp.StatusCode, jwksURL)
		return JWKS{}, fmt.Errorf("%s", errMsg)
	}

	var jwks JWKS

	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return JWKS{}, fmt.Errorf("failed to decode json response %w", err)
	}

	return jwks, nil
}

// Gets the JWKS URL from the OIDC discovery document.
func fetchJWKSURL(ctx context.Context, baseURL string, client *http.Client) (string, error) {
	if baseURL == "" {
		return "", fmt.Errorf("base url can not be empty")
	}
	discoveryURL := strings.TrimSuffix(baseURL, "/") + oidcDiscoveryPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC discovery request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request get OIDC discovery endpoint (%s): %w", discoveryURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery request to %s returned non 200 status: %w", discoveryURL, err)
	}

	var discoveryDoc discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&discoveryDoc); err != nil {
		return "", fmt.Errorf("failed to decode OIDC discovery JSON from %s: %w", discoveryURL, err)
	}

	if discoveryDoc.JwksURI == "" {
		return "", fmt.Errorf("jwks_uri not found in discovery doc from %s", discoveryURL)
	}

	return discoveryDoc.JwksURI, nil
}
