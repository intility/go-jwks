package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	defaultHttpClientMaxIdleCon          = 10
	defaultHttpClientIdleConnTimeout     = 30 * time.Second
	defaultHttpClientTLSHandshakeTimeout = 30 * time.Second
	defaultFetchInterval                 = 24 * time.Hour
	defaultTimeout                       = 60 * time.Second
	defaultMaxResponseSize               = 1 * 1024 * 1024 // 1MB - typical JWKS are <10KB
	defaultMaxKeysCount                  = 100             // Most providers have <10 keys
)

type discoveryDocument struct {
	JwksURI string `json:"jwks_uri"`
}

type JWKSFetcher struct {
	jwksURL         string
	jwks            *JWKS
	mutex           *sync.RWMutex
	fetchInterval   time.Duration
	httpClient      *http.Client
	logger          *slog.Logger
	maxResponseSize int64
	maxKeysCount    int
}

// JWKSFetcherOpts holds the confifuration for the JWKSFetcher.
type JWKSFetcherOpts struct {
	fetchInterval             time.Duration
	tlsHandshakeTimeout       time.Duration
	timeout                   time.Duration
	httpClientIdleConnTimeout time.Duration
	httpClientMaxIdleCon      int
	logger                    *slog.Logger
	maxResponseSize           int64 // Maximum size of JWKS response in bytes
	maxKeysCount              int   // Maximum number of keys allowed in JWKS
}

// Where the keyfetcher will fetch its public keys from.
type keySource interface {
	getDiscoveryEndpoint() (string, error)
}

// Provides configuration for getching keys from Microsoft EntraID.
type EntraID struct {
	TenantID string
}

// Provides configuration for fetching keys from a generic OIDC provider.
// Specify a full discovery document URL like https://<domain>/v2.0/.well-known/openid-configuration.
type Generic struct {
	DiscoveryURL string
}

// NewJWKSFetcher creates a new JWKSFetcher from a keySource.
func NewJWKSFetcher(source keySource, options ...Option) (*JWKSFetcher, error) {
	// Set default fetcher opts
	opts := &JWKSFetcherOpts{
		fetchInterval:             defaultFetchInterval,
		tlsHandshakeTimeout:       defaultHttpClientTLSHandshakeTimeout,
		timeout:                   defaultTimeout,
		httpClientIdleConnTimeout: defaultHttpClientIdleConnTimeout,
		httpClientMaxIdleCon:      defaultHttpClientMaxIdleCon,
		logger:                    slog.Default(),
		maxResponseSize:           defaultMaxResponseSize,
		maxKeysCount:              defaultMaxKeysCount,
	}

	// Apply options set by user
	for _, opt := range options {
		err := opt(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to construct JWKSFetcher: %w", err)
		}
	}

	httpClient := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        opts.httpClientMaxIdleCon,
			IdleConnTimeout:     opts.httpClientIdleConnTimeout,
			TLSHandshakeTimeout: opts.tlsHandshakeTimeout,
		},
	}

	discoveryURL, err := source.getDiscoveryEndpoint()
	if err != nil {
		return nil, fmt.Errorf("failed to set discovery url: %w", err)
	}

	jwksURL, err := fetchJWKSURL(context.Background(), discoveryURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS URL from discoveryURR '%s': %w", discoveryURL, err)
	}

	return &JWKSFetcher{
		jwksURL:         jwksURL,
		mutex:           &sync.RWMutex{},
		jwks:            nil,
		fetchInterval:   opts.fetchInterval,
		httpClient:      httpClient,
		logger:          opts.logger,
		maxResponseSize: opts.maxResponseSize,
		maxKeysCount:    opts.maxKeysCount,
	}, nil
}

// Start synchronization of JWKS into in-memory store.
// Performs an initial synchronous fetch to ensure keys are available before returning,
// then starts a background goroutine for periodic updates.
func (f *JWKSFetcher) Start(ctx context.Context) error {
	f.logger.DebugContext(ctx, "starting JWKS fetcher", "interval", f.fetchInterval)

	// Perform initial fetch synchronously.
	if err := f.synchronizeKeys(ctx); err != nil {
		f.logger.Error("initial key fetch failed", "error", err)
		return fmt.Errorf("initial key fetch failed: %w", err)
	}

	// Start background synchronization.
	go func() {
		ticker := time.NewTicker(f.fetchInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				f.logger.InfoContext(ctx, "jwks sync stopped")
				return
			case <-ticker.C:
				if err := f.synchronizeKeys(ctx); err != nil {
					f.logger.Error("failed to fetch remote keys", "error", err)
				}
			}
		}
	}()

	return nil
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

	// Limit the response body size to prevent memory exhaustion
	limitedReader := io.LimitReader(resp.Body, f.maxResponseSize)

	var jwks JWKS
	err = json.NewDecoder(limitedReader).Decode(&jwks)
	if err != nil {
		return JWKS{}, fmt.Errorf("failed to decode json response: %w", err)
	}

	// Validate the number of keys to prevent excessive memory allocation
	if len(jwks.Keys) > f.maxKeysCount {
		return JWKS{}, fmt.Errorf("JWKS response contains %d keys, exceeding maximum of %d", len(jwks.Keys), f.maxKeysCount)
	}

	return jwks, nil
}

// Gets the JWKS URL from the OIDC discovery document.
func fetchJWKSURL(ctx context.Context, discoveryURL string, client *http.Client) (string, error) {
	if discoveryURL == "" {
		return "", fmt.Errorf("discovery url can not be empty")
	}

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

func (e EntraID) getDiscoveryEndpoint() (string, error) {
	if e.TenantID == "" {
		return "", fmt.Errorf("tenant ID must be set when using entra ID source")
	}

	return fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", e.TenantID), nil
}

func (g Generic) getDiscoveryEndpoint() (string, error) {
	if g.DiscoveryURL == "" {
		return "", fmt.Errorf("discovery url cannot be empty")
	}

	_, err := url.ParseRequestURI(g.DiscoveryURL)
	if err != nil {
		return "", fmt.Errorf("invalid DiscoveryURL: %w", err)
	}

	return g.DiscoveryURL, nil
}

// Option is a function that configures a JWKSFetcherOpts.
type Option func(*JWKSFetcherOpts) error

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

// WithDebugLog lets you override the standard logger.
func WithLogger(logger *slog.Logger) Option {
	return func(o *JWKSFetcherOpts) error {
		o.logger = logger
		return nil
	}
}

// WithMaxResponseSize sets the maximum allowed size for JWKS responses.
// This prevents memory exhaustion attacks from malicious JWKS endpoints.
func WithMaxResponseSize(size int64) Option {
	return func(o *JWKSFetcherOpts) error {
		if size <= 0 {
			return fmt.Errorf("WithMaxResponseSize: size must be positive")
		}
		o.maxResponseSize = size
		return nil
	}
}

// WithMaxKeysCount sets the maximum number of keys allowed in a JWKS response.
// This prevents excessive memory allocation from malicious responses.
func WithMaxKeysCount(count int) Option {
	return func(o *JWKSFetcherOpts) error {
		if count <= 0 {
			return fmt.Errorf("WithMaxKeysCount: count must be positive")
		}
		o.maxKeysCount = count
		return nil
	}
}
