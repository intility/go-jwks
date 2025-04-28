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

type JWKSFetcherOpts struct {
	BaseURL                   string
	FetchInterval             time.Duration
	TLSHandshakeTimeout       time.Duration
	Timeout                   time.Duration
	HttpClientIdleConnTimeout time.Duration
	HttpClientMaxIdleCon      int
	DebugLog                  bool
}

func NewJWKSFetcher(opts *JWKSFetcherOpts) (*JWKSFetcher, error) {
	setDefaults(opts)

	httpClient := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        opts.HttpClientMaxIdleCon,
			IdleConnTimeout:     opts.HttpClientIdleConnTimeout,
			TLSHandshakeTimeout: opts.TLSHandshakeTimeout,
		},
	}

	jwksURL, err := fetchJWKSURL(context.Background(), opts.BaseURL, httpClient)
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
		fetchInterval: opts.FetchInterval,
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

func setDefaults(opts *JWKSFetcherOpts) {
	if opts.FetchInterval == 0 {
		opts.FetchInterval = defaultFetchInterval
	}
	if opts.TLSHandshakeTimeout == 0 {
		opts.TLSHandshakeTimeout = defaultHttpClientTLSHandshakeTimeout
	}
	if opts.Timeout == 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.HttpClientMaxIdleCon == 0 {
		opts.HttpClientMaxIdleCon = defaultHttpClientMaxIdleCon
	}
	if opts.HttpClientIdleConnTimeout == 0 {
		opts.HttpClientIdleConnTimeout = defaultHttpClientIdleConnTimeout
	}
}
