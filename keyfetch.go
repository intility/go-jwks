package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	defaultHttpClientMaxIdleCon          = 10
	defaultHttpClientIdleConnTimeout     = 30 * time.Second
	defaultHttpClientTLSHandshakeTimeout = 30 * time.Second
	defaultFetchInterval                 = 24 * time.Hour
	defaultTimeout                       = 60 * time.Second
)

type JWKSFetcher struct {
	wellKnowURL   string
	jwks          *JWKS
	mutex         *sync.RWMutex
	fetchInterval time.Duration
	httpClient    *http.Client
}

type JWKSFetcherOpts struct {
	BaseURL                   string
	FetchInterval             time.Duration
	TLSHandshakeTimeout       time.Duration
	Timeout                   time.Duration
	HttpClientIdleConnTimeout time.Duration
	HttpClientMaxIdleCon      int
}

func NewJWKSFetcher(opts *JWKSFetcherOpts) (*JWKSFetcher, error) {
	if opts.BaseURL == "" {
		return nil, fmt.Errorf("base url is required")
	}

	setDefaults(opts)

	httpClient := &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        opts.HttpClientMaxIdleCon,
			IdleConnTimeout:     opts.HttpClientIdleConnTimeout,
			DisableCompression:  true,
			TLSHandshakeTimeout: opts.TLSHandshakeTimeout,
		},
	}

	return &JWKSFetcher{
		wellKnowURL:   createDiscoveryURL(opts.BaseURL),
		mutex:         &sync.RWMutex{},
		jwks:          nil,
		fetchInterval: opts.FetchInterval,
		httpClient:    httpClient,
	}, nil
}

// Start synchronization of JWKS into in-memory store.
func (f *JWKSFetcher) Start(ctx context.Context) {
	go func() {
		slog.Info("performing intitial fetch")
		if err := f.synchronizeKeys(ctx); err != nil {
			slog.Error("initial JWKS fetch failed", "error", err)
		}

		ticker := time.NewTicker(f.fetchInterval)
		defer ticker.Stop()

		for {
			slog.Info("fetching new keys")
			if err := f.synchronizeKeys(ctx); err != nil {
				slog.Error("failed to fetch remote keys", "error", err)
			}

			select {
			case <-ctx.Done():
				slog.Info("jwks sync stopped")
				return
			case <-ticker.C:
				continue
			}
		}
	}()
}

func (f *JWKSFetcher) fetchRemoteJWKS(ctx context.Context, jwksURL string) (JWKS, error) {
	slog.DebugContext(ctx, "Starting fetchRemoteJWKS")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return JWKS{}, fmt.Errorf("crafting request to %s failed with %w", jwksURL, err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		slog.DebugContext(ctx, "failed request", "url", jwksURL, "error", err)
		return JWKS{}, fmt.Errorf("request to %s failed with %w", jwksURL, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		slog.ErrorContext(ctx, "received non 200 status from JWKS url", "url", jwksURL, "status code", resp.StatusCode)
	}

	var jwks JWKS

	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		slog.DebugContext(ctx, "failed to decode json response from JWKS url", "error", err)
		return JWKS{}, fmt.Errorf("failed to decode json response %w", err)
	}

	slog.DebugContext(ctx, "fetchRemoteJWKS done")

	return jwks, nil
}

func (f *JWKSFetcher) synchronizeKeys(ctx context.Context) error {
	slog.DebugContext(ctx, "Refreshing JWKS keys")

	newJWKS, err := f.fetchRemoteJWKS(ctx, f.wellKnowURL)
	if err != nil {
		return fmt.Errorf("failed to fetch remote keys: %w", err)
	}

	f.mutex.Lock()
	f.jwks = &newJWKS
	f.mutex.Unlock()

	slog.DebugContext(ctx, "JWKS keys refreshed successfully")

	return nil
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
