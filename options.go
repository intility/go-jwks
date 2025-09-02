package jwt

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"
)

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

// WithTLSConfig sets a custom TLS configuration for JWKS fetching.
// If not set, a secure default configuration with TLS 1.2+ and strong cipher suites is used.
// Use this option if you need specific TLS settings for your environment.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(o *JWKSFetcherOpts) error {
		if tlsConfig == nil {
			return fmt.Errorf("WithTLSConfig: tlsConfig cannot be nil")
		}
		o.tlsConfig = tlsConfig
		return nil
	}
}

// WithRequireHTTPS controls whether HTTPS is required for JWKS URLs.
// By default, HTTPS is required for security (true).
// Set to false only in secure environments like airgapped networks or internal systems
// where TLS termination happens at a different layer.
func WithRequireHTTPS(require bool) Option {
	return func(o *JWKSFetcherOpts) error {
		o.requireHTTPS = require
		return nil
	}
}

// WithAllowedJWKSHosts sets an allowlist of hostnames for JWKS URLs.
// If set, only JWKS URLs from these hosts will be accepted.
// If not set (default), all hosts are allowed for backward compatibility.
// This validates the JWKS URL from the discovery document, not the discovery URL itself.
func WithAllowedJWKSHosts(hosts []string) Option {
	return func(o *JWKSFetcherOpts) error {
		if len(hosts) == 0 {
			return fmt.Errorf("WithAllowedJWKSHosts: hosts list cannot be empty (use nil for no restriction)")
		}
		o.allowedJWKSHosts = hosts
		return nil
	}
}

// WithMicrosoftHosts configures the fetcher to only accept JWKS from known Microsoft endpoints.
// This includes common Microsoft Entra ID (formerly Azure AD) domains.
func WithMicrosoftHosts() Option {
	return func(o *JWKSFetcherOpts) error {
		o.allowedJWKSHosts = []string{
			"login.microsoftonline.com",
			"login.microsoft.com",
			"login.windows.net",
			"sts.windows.net",
		}
		return nil
	}
}