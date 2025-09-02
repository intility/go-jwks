package jwt

import (
	"context"
	"crypto/tls"
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
	maxResponseSize           int64       // Maximum size of JWKS response in bytes
	maxKeysCount              int         // Maximum number of keys allowed in JWKS
	tlsConfig                 *tls.Config // TLS configuration for HTTPS connections
	requireHTTPS              bool        // Require HTTPS for JWKS URLs (true by default for security)
	allowedJWKSHosts          []string    // Allowlist of hostnames for JWKS URLs (empty allows all)
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

// defaultTLSConfig returns a secure TLS configuration with modern standards.
func defaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12, // Require TLS 1.2 minimum
		InsecureSkipVerify: false,            // Always verify certificates
		// Cipher suites intentionally not set - Go's defaults are secure and
		// automatically updated with each release to use the best available options
	}
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
		tlsConfig:                 defaultTLSConfig(), // Use secure defaults
		requireHTTPS:              true,               // Require HTTPS by default for security
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
			TLSClientConfig:     opts.tlsConfig,
		},
	}

	discoveryURL, err := source.getDiscoveryEndpoint()
	if err != nil {
		return nil, fmt.Errorf("failed to set discovery url: %w", err)
	}

	jwksURL, err := fetchJWKSURL(context.Background(), discoveryURL, httpClient, opts.requireHTTPS, opts.allowedJWKSHosts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS URL from discoveryURL '%s': %w", discoveryURL, err)
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

// validateHost checks if a URL's host is in the allowed list.
// If allowedHosts is empty, all hosts are allowed (backward compatibility).
func validateHost(urlStr string, allowedHosts []string, urlType string) error {
	if len(allowedHosts) == 0 {
		return nil // No restriction if allowlist is empty
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("failed to parse %s URL: %w", urlType, err)
	}

	// Get hostname without port for comparison
	hostname := parsed.Hostname()
	
	for _, allowed := range allowedHosts {
		if hostname == allowed {
			return nil
		}
	}

	return fmt.Errorf("%s host '%s' is not in the allowed hosts list", urlType, hostname)
}

// Gets the JWKS URL from the OIDC discovery document.
func fetchJWKSURL(ctx context.Context, discoveryURL string, client *http.Client, requireHTTPS bool, allowedHosts []string) (string, error) {
	if discoveryURL == "" {
		return "", fmt.Errorf("discovery url can not be empty")
	}

	// Validate discovery URL uses HTTPS if required
	if requireHTTPS {
		discoveryParsed, err := url.Parse(discoveryURL)
		if err != nil {
			return "", fmt.Errorf("failed to parse discovery URL: %w", err)
		}
		if discoveryParsed.Scheme != "https" {
			return "", fmt.Errorf("discovery URL must use HTTPS, got scheme: %s (use WithRequireHTTPS(false) to allow HTTP in secure environments)", discoveryParsed.Scheme)
		}
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

	// Validate JWKS URL host is allowed
	if err := validateHost(discoveryDoc.JwksURI, allowedHosts, "JWKS"); err != nil {
		return "", err
	}

	// Validate JWKS URL uses HTTPS if required
	if requireHTTPS {
		jwksParsed, err := url.Parse(discoveryDoc.JwksURI)
		if err != nil {
			return "", fmt.Errorf("failed to parse JWKS URL from discovery document: %w", err)
		}
		if jwksParsed.Scheme != "https" {
			return "", fmt.Errorf("JWKS URL must use HTTPS for security, got: %s (use WithRequireHTTPS(false) to allow HTTP in secure environments)", discoveryDoc.JwksURI)
		}
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

	// Validate it's a valid URL
	_, err := url.ParseRequestURI(g.DiscoveryURL)
	if err != nil {
		return "", fmt.Errorf("invalid DiscoveryURL: %w", err)
	}

	// HTTPS validation is now done in fetchJWKSURL based on requireHTTPS option
	return g.DiscoveryURL, nil
}