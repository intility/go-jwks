package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jwtpkg "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Test timing constants.
	testNetworkDelay      = 50 * time.Millisecond
	testFetchInterval     = 100 * time.Millisecond
	testBackgroundWait    = 150 * time.Millisecond
	testConcurrentWorkers = 5

	// Test key sizes.
	testRSAKeySize = 2048

	// URL paths.
	jwksPath                = "/jwks"
	openIDConfigurationPath = "/.well-known/openid-configuration"
)

// mockJWKSServer creates a test server that responds with discovery and JWKS endpoints.
// It returns the server and a function to get the current call count.
func mockJWKSServer(t *testing.T, jwksResponses ...*JWKS) (*httptest.Server, func() int) {
	t.Helper()

	var (
		callCount int
		mu        sync.Mutex
		serverURL string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == jwksPath {
			mu.Lock()
			currentCall := callCount
			callCount++
			mu.Unlock()

			// Return different JWKS based on call count if multiple responses provided
			if len(jwksResponses) > 0 {
				responseIndex := currentCall
				if responseIndex >= len(jwksResponses) {
					responseIndex = len(jwksResponses) - 1
				}
				if err := json.NewEncoder(w).Encode(jwksResponses[responseIndex]); err != nil {
					http.Error(w, "Failed to encode JWKS response", http.StatusInternalServerError)
					return
				}
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		} else {
			// Return discovery document for any other path
			discovery := map[string]interface{}{
				"jwks_uri": serverURL + "/jwks",
				"issuer":   "http://example.com",
			}
			if err := json.NewEncoder(w).Encode(discovery); err != nil {
				http.Error(w, "Failed to encode discovery response", http.StatusInternalServerError)
				return
			}
		}
	}))

	serverURL = server.URL

	getCallCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return callCount
	}

	return server, getCallCount
}

// generateTestKey creates a test RSA private key.
func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, testRSAKeySize)
	require.NoError(t, err, "failed to generate RSA key")
	return privateKey
}

// TestStartInitialFetchSync verifies that Start() performs initial fetch synchronously
// and that keys are available immediately after Start() returns.
func TestStartInitialFetchSync(t *testing.T) {
	// Setup
	privateKey := generateTestKey(t)
	jwks := createTestJWKS(privateKey, "test-key-1")
	server, _ := mockJWKSServer(t, jwks)
	defer server.Close()

	// Create fetcher with the test server URL as discovery endpoint
	// Use WithRequireHTTPS(false) for local testing with HTTP
	fetcher, err := NewJWKSFetcher(Generic{DiscoveryURL: server.URL}, WithRequireHTTPS(false))
	require.NoError(t, err, "failed to create JWKS fetcher")

	ctx := context.Background()

	// Verify keys are nil before Start
	fetcher.mutex.RLock()
	assert.Nil(t, fetcher.jwks, "keys should be nil before Start()")
	fetcher.mutex.RUnlock()

	// Act: Start should perform initial fetch synchronously
	err = fetcher.Start(ctx)
	require.NoError(t, err, "Start() should succeed with valid JWKS")

	// Assert: Keys should be available immediately after Start returns
	fetcher.mutex.RLock()
	defer fetcher.mutex.RUnlock()
	assert.NotNil(t, fetcher.jwks, "keys should be available immediately after Start()")
	assert.Len(t, fetcher.jwks.Keys, 1, "should have fetched one key")
	assert.Equal(t, "test-key-1", fetcher.jwks.Keys[0].Kid, "should have correct key ID")
}

// TestStartInitialFetchError verifies that Start() returns an error
// when the initial fetch fails.
func TestStartInitialFetchError(t *testing.T) {
	// Setup: Create a server that will fail on JWKS endpoint
	server, _ := mockJWKSServer(t) // No JWKS responses = error
	defer server.Close()

	// Create fetcher with the test server URL as discovery endpoint
	// Use WithRequireHTTPS(false) for local testing with HTTP
	fetcher, err := NewJWKSFetcher(Generic{DiscoveryURL: server.URL}, WithRequireHTTPS(false))
	require.NoError(t, err, "failed to create JWKS fetcher")

	ctx := context.Background()

	// Act: Start should return an error when initial JWKS fetch fails
	err = fetcher.Start(ctx)

	// Assert: Verify error and state
	assert.Error(t, err, "Start() should return error when initial fetch fails")
	assert.Contains(t, err.Error(), "initial key fetch failed", "error should indicate initial fetch failure")

	// Keys should still be nil after failed Start
	fetcher.mutex.RLock()
	defer fetcher.mutex.RUnlock()
	assert.Nil(t, fetcher.jwks, "keys should remain nil after failed Start()")
}

// mockSlowJWKSServer creates a test server with simulated network delay.
func mockSlowJWKSServer(t *testing.T, delay time.Duration, jwks *JWKS) *httptest.Server {
	t.Helper()

	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err, "failed to marshal JWKS")

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay) // Simulate network delay
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == jwksPath {
			if _, err := w.Write(jwksJSON); err != nil {
				http.Error(w, "Failed to write JWKS response", http.StatusInternalServerError)
				return
			}
		} else {
			discovery := map[string]interface{}{
				"jwks_uri": serverURL + "/jwks",
				"issuer":   "http://example.com",
			}
			if err := json.NewEncoder(w).Encode(discovery); err != nil {
				http.Error(w, "Failed to encode discovery response", http.StatusInternalServerError)
				return
			}
		}
	}))
	serverURL = server.URL
	return server
}

// TestNoRaceConditionOnStartup verifies that there's no race condition
// between Start() and immediate use of the middleware.
func TestNoRaceConditionOnStartup(t *testing.T) {
	// Setup
	privateKey := generateTestKey(t)
	jwks := createTestJWKS(privateKey, "test-key-1")
	server := mockSlowJWKSServer(t, testNetworkDelay, jwks)
	defer server.Close()

	// Create fetcher
	fetcher, err := NewJWKSFetcher(Generic{DiscoveryURL: server.URL}, WithRequireHTTPS(false))
	require.NoError(t, err, "failed to create JWKS fetcher")

	ctx := context.Background()

	// Setup concurrent access test
	startChan := make(chan struct{})
	var wg sync.WaitGroup
	var (
		errors      []error
		errorsMutex sync.Mutex
	)

	// Start multiple goroutines that will try to access keys
	// immediately after Start() returns
	for i := 0; i < testConcurrentWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Wait for signal that Start() has been called
			<-startChan

			// Small random delay to simulate realistic timing
			time.Sleep(time.Duration(id) * time.Millisecond)

			// Try to access keys - should not be nil after Start() returns
			fetcher.mutex.RLock()
			defer fetcher.mutex.RUnlock()

			if fetcher.jwks == nil {
				errorsMutex.Lock()
				errors = append(errors, fmt.Errorf("goroutine %d: keys were nil when accessed", id))
				errorsMutex.Unlock()
			}
		}(i)
	}

	// Act: Start the fetcher (should block until initial fetch completes)
	err = fetcher.Start(ctx)
	require.NoError(t, err, "Start() should succeed")

	// Signal goroutines that Start() has completed
	close(startChan)

	// Wait for all goroutines to finish checking
	wg.Wait()

	// Assert: Verify no race conditions occurred
	assert.Empty(t, errors, "No goroutine should have found nil keys after Start() returned")
}

// TestBackgroundSyncContinuesAfterStart verifies that background synchronization
// continues after the initial fetch.
func TestBackgroundSyncContinuesAfterStart(t *testing.T) {
	// Setup: Create two different JWKS responses
	privateKey := generateTestKey(t)
	jwks1 := createTestJWKS(privateKey, "test-key-1")
	jwks2 := createTestJWKS(privateKey, "test-key-2")

	// Create test server that returns different JWKS on subsequent calls
	server, getCallCount := mockJWKSServer(t, jwks1, jwks2)
	defer server.Close()

	// Create fetcher with short fetch interval
	fetcher, err := NewJWKSFetcher(
		Generic{DiscoveryURL: server.URL},
		WithFetchInterval(testFetchInterval),
		WithRequireHTTPS(false), // Allow HTTP for testing
	)
	require.NoError(t, err, "failed to create JWKS fetcher")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Act: Start the fetcher
	err = fetcher.Start(ctx)
	require.NoError(t, err, "Start() should succeed")

	// Assert: Verify initial key
	fetcher.mutex.RLock()
	assert.Equal(t, "test-key-1", fetcher.jwks.Keys[0].Kid, "initial key should be test-key-1")
	fetcher.mutex.RUnlock()

	// Wait for background sync to update keys
	time.Sleep(testBackgroundWait)

	// Assert: Verify keys were updated by background sync
	fetcher.mutex.RLock()
	assert.Equal(t, "test-key-2", fetcher.jwks.Keys[0].Kid, "background sync should have updated to test-key-2")
	fetcher.mutex.RUnlock()

	// Assert: Verify multiple fetches occurred
	assert.GreaterOrEqual(t, getCallCount(), 2, "should have fetched at least twice (initial + background)")
}

// createTestJWKS creates a test JWKS with the given RSA key and key ID.
func createTestJWKS(privateKey *rsa.PrivateKey, kid string) *JWKS {
	n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes())

	return &JWKS{
		Keys: []JSONWebKey{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: kid,
				N:   n,
				E:   e,
			},
		},
	}
}

// TestMaxResponseSize tests that the fetcher respects the maximum response size limit.
func TestMaxResponseSize(t *testing.T) {
	// Create a large JWKS response that exceeds the limit
	largeKey := JSONWebKey{
		Kid: "test-key",
		Kty: "RSA",
		Use: "sig",
		N:   strings.Repeat("A", 10000), // Large N value to make response big
		E:   "AQAB",
	}

	largeJWKS := JWKS{
		Keys: []JSONWebKey{largeKey},
	}

	// Set up test server that returns the large JWKS
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case openIDConfigurationPath:
			discovery := map[string]string{
				"jwks_uri": serverURL + "/jwks",
			}
			if err := json.NewEncoder(w).Encode(discovery); err != nil {
				http.Error(w, "Failed to encode discovery response", http.StatusInternalServerError)
				return
			}
		case jwksPath:
			// Return a large response
			if err := json.NewEncoder(w).Encode(largeJWKS); err != nil {
				http.Error(w, "Failed to encode large JWKS response", http.StatusInternalServerError)
				return
			}
		}
	}))
	serverURL = server.URL
	defer server.Close()

	// Create fetcher with small max response size
	fetcher, err := NewJWKSFetcher(
		Generic{DiscoveryURL: server.URL + "/.well-known/openid-configuration"},
		WithMaxResponseSize(100), // Very small limit
		WithRequireHTTPS(false),  // Allow HTTP for testing
	)
	require.NoError(t, err)

	// Try to fetch - should fail due to size limit
	jwks, err := fetcher.fetchRemoteJWKS(context.Background(), server.URL+"/jwks")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode json response")
	assert.Empty(t, jwks.Keys)
}

// TestMaxKeysCount tests that the fetcher respects the maximum keys count limit.
func TestMaxKeysCount(t *testing.T) {
	// Create JWKS with many keys
	var keys []JSONWebKey
	for i := 0; i < 20; i++ {
		keys = append(keys, JSONWebKey{
			Kid: fmt.Sprintf("key-%d", i),
			Kty: "RSA",
			Use: "sig",
			N:   "test-n",
			E:   "AQAB",
		})
	}

	manyKeysJWKS := JWKS{Keys: keys}

	// Set up test server
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case openIDConfigurationPath:
			discovery := map[string]string{
				"jwks_uri": serverURL + "/jwks",
			}
			if err := json.NewEncoder(w).Encode(discovery); err != nil {
				http.Error(w, "Failed to encode discovery response", http.StatusInternalServerError)
				return
			}
		case jwksPath:
			if err := json.NewEncoder(w).Encode(manyKeysJWKS); err != nil {
				http.Error(w, "Failed to encode many keys JWKS response", http.StatusInternalServerError)
				return
			}
		}
	}))
	serverURL = server.URL
	defer server.Close()

	// Create fetcher with small max keys count
	fetcher, err := NewJWKSFetcher(
		Generic{DiscoveryURL: server.URL + "/.well-known/openid-configuration"},
		WithMaxKeysCount(10),    // Allow only 10 keys
		WithRequireHTTPS(false), // Allow HTTP for testing
	)
	require.NoError(t, err)

	// Try to fetch - should fail due to keys count limit
	jwks, err := fetcher.fetchRemoteJWKS(context.Background(), server.URL+"/jwks")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeding maximum of 10")
	assert.Empty(t, jwks.Keys)
}

// TestJWKSHostValidation tests that JWKS host validation works correctly with allowlisting.
func TestJWKSHostValidation(t *testing.T) {
	// Generate test key
	privateKey := generateTestKey(t)
	jwks := createTestJWKS(privateKey, "test-key-1")

	t.Run("allow all hosts when no allowlist", func(t *testing.T) {
		// Setup test server
		var serverURL string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				// Return discovery doc with JWKS URL
				discovery := map[string]string{
					"jwks_uri": serverURL + "/jwks",
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(discovery); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			case "/jwks":
				// Return JWKS
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(jwks); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}
		}))
		defer server.Close()
		serverURL = server.URL

		// Create fetcher without host restrictions
		fetcher, err := NewJWKSFetcher(
			Generic{DiscoveryURL: server.URL + "/.well-known/openid-configuration"},
			WithRequireHTTPS(false), // Allow HTTP for testing
		)
		require.NoError(t, err)
		assert.NotNil(t, fetcher)
	})

	t.Run("reject JWKS from non-allowed host", func(t *testing.T) {
		// Setup test server that returns JWKS URL with different host
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return discovery doc with external JWKS URL
			discovery := map[string]string{
				"jwks_uri": "http://evil.com/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(discovery); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		// Create fetcher with host restrictions
		_, err := NewJWKSFetcher(
			Generic{DiscoveryURL: server.URL + "/.well-known/openid-configuration"},
			WithRequireHTTPS(false), // Allow HTTP for testing
			WithAllowedJWKSHosts([]string{"trusted.com"}),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "JWKS host 'evil.com' is not in the allowed hosts list")
	})

	t.Run("accept JWKS from allowed host", func(t *testing.T) {
		// Setup test server
		var serverURL string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				// Return discovery doc with JWKS URL using same host
				discovery := map[string]string{
					"jwks_uri": serverURL + "/jwks",
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(discovery); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			case "/jwks":
				// Return JWKS
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(jwks); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}
		}))
		defer server.Close()
		serverURL = server.URL

		// Parse server URL to get hostname
		parsedURL, _ := url.Parse(server.URL)

		// Create fetcher with host restrictions allowing test server
		fetcher, err := NewJWKSFetcher(
			Generic{DiscoveryURL: server.URL + "/.well-known/openid-configuration"},
			WithRequireHTTPS(false), // Allow HTTP for testing
			WithAllowedJWKSHosts([]string{parsedURL.Hostname()}),
		)
		require.NoError(t, err)
		assert.NotNil(t, fetcher)
	})

	t.Run("Microsoft hosts preset", func(t *testing.T) {
		// This tests that the WithMicrosoftHosts option sets the expected hosts
		opts := &JWKSFetcherOpts{}
		err := WithMicrosoftHosts()(opts)
		require.NoError(t, err)

		expectedHosts := []string{
			"login.microsoftonline.com",
			"login.microsoft.com",
			"login.windows.net",
			"sts.windows.net",
		}
		assert.ElementsMatch(t, expectedHosts, opts.allowedJWKSHosts)
	})
}

// TestMalformedJWKSResponses tests that the fetcher handles malformed JWKS responses gracefully without panicking.
func TestMalformedJWKSResponses(t *testing.T) {
	testCases := []struct {
		name          string
		jwksResponse  string
		expectedError string
	}{
		// Invalid JSON responses
		{
			name:          "completely invalid JSON",
			jwksResponse:  `{invalid json`,
			expectedError: "failed to decode json response",
		},
		{
			name:          "truncated JSON",
			jwksResponse:  `{"keys": [`,
			expectedError: "failed to decode json response",
		},
		{
			name:          "keys field is not an array",
			jwksResponse:  `{"keys": "not-an-array"}`,
			expectedError: "failed to decode json response",
		},
		// Missing required fields
		{
			name:          "missing keys array",
			jwksResponse:  `{}`,
			expectedError: "", // Valid JWKS structure (keys array is optional), will result in empty key set
		},
		{
			name:          "empty keys array",
			jwksResponse:  `{"keys": []}`,
			expectedError: "", // Valid JWKS with no keys, will result in empty key set
		},
		{
			name:          "missing kid field",
			jwksResponse:  `{"keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB", "use": "sig"}]}`,
			expectedError: "", // JWKS fetch succeeds; error occurs during key lookup when kid is needed
		},
		{
			name:          "missing kty field",
			jwksResponse:  `{"keys": [{"kid": "test", "n": "AQAB", "e": "AQAB", "use": "sig"}]}`,
			expectedError: "", // JWKS fetch succeeds; parseKey will fail with "method not supported: "
		},
		{
			name:          "missing RSA n parameter",
			jwksResponse:  `{"keys": [{"kid": "test", "kty": "RSA", "e": "AQAB", "use": "sig"}]}`,
			expectedError: "", // JWKS fetch succeeds; parseKey will fail with "missing N and/or E param"
		},
		{
			name:          "missing RSA e parameter",
			jwksResponse:  `{"keys": [{"kid": "test", "kty": "RSA", "n": "AQAB", "use": "sig"}]}`,
			expectedError: "", // JWKS fetch succeeds; parseKey will fail with "missing N and/or E param"
		},
		// Invalid base64 encoding
		{
			name:          "invalid base64 in n parameter",
			jwksResponse:  `{"keys": [{"kid": "test", "kty": "RSA", "n": "!!!invalid-base64!!!", "e": "AQAB", "use": "sig"}]}`,
			expectedError: "", // JWKS fetch succeeds; parseKey will fail with "failed to decode RSA modulus 'n'"
		},
		{
			name:          "invalid base64 in e parameter",
			jwksResponse:  `{"keys": [{"kid": "test", "kty": "RSA", "n": "AQAB", "e": "!!!invalid-base64!!!", "use": "sig"}]}`,
			expectedError: "", // JWKS fetch succeeds; parseKey will fail with "failed to decode RSA modulus 'e'"
		},
		// Cryptographic edge cases
		{
			name:          "zero value modulus",
			jwksResponse:  `{"keys": [{"kid": "test", "kty": "RSA", "n": "AA", "e": "AQAB", "use": "sig"}]}`,
			expectedError: "", // JWKS fetch succeeds; parseKey will fail with "RSA modulus or exponent resulted in zero value"
		},
		{
			name:          "zero value exponent",
			jwksResponse:  `{"keys": [{"kid": "test", "kty": "RSA", "n": "AQAB", "e": "AA", "use": "sig"}]}`,
			expectedError: "", // JWKS fetch succeeds; parseKey will fail with "RSA modulus or exponent resulted in zero value"
		},
		// Unsupported key type
		{
			name:          "unsupported key type",
			jwksResponse:  `{"keys": [{"kid": "test", "kty": "EC", "crv": "P-256", "x": "test", "y": "test"}]}`,
			expectedError: "", // JWKS fetch succeeds; parseKey will fail with "EC not yet supported"
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test server that returns malformed JWKS
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case openIDConfigurationPath:
					discovery := map[string]string{
						"jwks_uri": r.Host + "/jwks",
					}
					if !strings.HasPrefix(r.Host, "http") {
						discovery["jwks_uri"] = "http://" + discovery["jwks_uri"]
					}
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(discovery); err != nil {
						http.Error(w, "Failed to encode discovery", http.StatusInternalServerError)
					}
				case jwksPath:
					// Return the malformed response
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(tc.jwksResponse))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			// Create fetcher
			fetcher, err := NewJWKSFetcher(
				Generic{DiscoveryURL: server.URL + openIDConfigurationPath},
				WithRequireHTTPS(false), // Allow HTTP for testing
			)
			require.NoError(t, err, "Failed to create fetcher")

			// Try to fetch JWKS
			jwks, err := fetcher.fetchRemoteJWKS(context.Background(), server.URL+jwksPath)

			if tc.expectedError != "" {
				// Should fail with expected error
				assert.Error(t, err, "Expected error for %s", tc.name)
				assert.Contains(t, err.Error(), tc.expectedError, "Error message should contain expected text")
			} else {
				// Should succeed but might have empty or invalid keys
				assert.NoError(t, err, "Should not error during fetch for %s", tc.name)
				// The actual validation will happen during key parsing
				_ = jwks
			}
		})
	}
}

// TestMalformedDiscoveryDocument tests that the fetcher handles malformed discovery documents gracefully.
func TestMalformedDiscoveryDocument(t *testing.T) {
	testCases := []struct {
		name              string
		discoveryResponse string
		expectedError     string
	}{
		{
			name:              "invalid JSON in discovery document",
			discoveryResponse: `{invalid json`,
			expectedError:     "failed to decode OIDC discovery JSON",
		},
		{
			name:              "missing jwks_uri field",
			discoveryResponse: `{"issuer": "http://example.com"}`,
			expectedError:     "jwks_uri not found in discovery doc",
		},
		{
			name:              "empty jwks_uri field",
			discoveryResponse: `{"jwks_uri": ""}`,
			expectedError:     "jwks_uri not found in discovery doc",
		},
		{
			name:              "jwks_uri is not a string",
			discoveryResponse: `{"jwks_uri": 123}`,
			expectedError:     "failed to decode OIDC discovery JSON",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test server that returns malformed discovery document
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.discoveryResponse))
			}))
			defer server.Close()

			// Try to create fetcher - should fail during discovery fetch
			_, err := NewJWKSFetcher(
				Generic{DiscoveryURL: server.URL},
				WithRequireHTTPS(false), // Allow HTTP for testing
			)

			assert.Error(t, err, "Expected error for %s", tc.name)
			assert.Contains(t, err.Error(), tc.expectedError, "Error message should contain expected text")
		})
	}
}

// TestParseKeyEdgeCases tests that parseKey handles cryptographic edge cases properly.
func TestParseKeyEdgeCases(t *testing.T) {
	testCases := []struct {
		name          string
		key           JSONWebKey
		expectedError string
	}{
		{
			name: "valid RSA key",
			key: JSONWebKey{
				Kid: "test",
				Kty: "RSA",
				N:   "AQAB",
				E:   "AQAB",
			},
			expectedError: "",
		},
		{
			name: "missing N parameter",
			key: JSONWebKey{
				Kid: "test",
				Kty: "RSA",
				E:   "AQAB",
			},
			expectedError: "missing N and/or E param",
		},
		{
			name: "missing E parameter",
			key: JSONWebKey{
				Kid: "test",
				Kty: "RSA",
				N:   "AQAB",
			},
			expectedError: "missing N and/or E param",
		},
		{
			name: "invalid base64 in N",
			key: JSONWebKey{
				Kid: "test",
				Kty: "RSA",
				N:   "!!!invalid!!!",
				E:   "AQAB",
			},
			expectedError: "failed to decode RSA modulus 'n'",
		},
		{
			name: "invalid base64 in E",
			key: JSONWebKey{
				Kid: "test",
				Kty: "RSA",
				N:   "AQAB",
				E:   "!!!invalid!!!",
			},
			expectedError: "failed to decode RSA modulus 'e'",
		},
		{
			name: "zero value modulus",
			key: JSONWebKey{
				Kid: "test",
				Kty: "RSA",
				N:   "AA", // Base64 of 0
				E:   "AQAB",
			},
			expectedError: "RSA modulus or exponent resulted in zero value",
		},
		{
			name: "zero value exponent",
			key: JSONWebKey{
				Kid: "test",
				Kty: "RSA",
				N:   "AQAB",
				E:   "AA", // Base64 of 0
			},
			expectedError: "RSA modulus or exponent resulted in zero value",
		},
		{
			name: "exponent too large for int64",
			key: JSONWebKey{
				Kid: "test",
				Kty: "RSA",
				N:   "AQAB",
				// This creates a number larger than MaxInt64
				E: base64.RawURLEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
			},
			expectedError: "RSA exponent 'e' is too big to fit in an int",
		},
		{
			name: "unsupported EC key type",
			key: JSONWebKey{
				Kid: "test",
				Kty: "EC",
			},
			expectedError: "EC not yet supported",
		},
		{
			name: "unknown key type",
			key: JSONWebKey{
				Kid: "test",
				Kty: "UNKNOWN",
			},
			expectedError: "method not supported",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseKey(&tc.key)

			if tc.expectedError != "" {
				assert.Error(t, err, "Expected error for %s", tc.name)
				assert.Contains(t, err.Error(), tc.expectedError, "Error message should contain expected text")
				assert.Nil(t, result, "Result should be nil on error")
			} else {
				assert.NoError(t, err, "Should not error for %s", tc.name)
				assert.NotNil(t, result, "Result should not be nil on success")
			}
		})
	}
}

// TestMixedValidInvalidKeys tests that the fetcher can handle JWKS responses
// containing both valid and invalid keys, successfully parsing valid ones while
// gracefully handling invalid entries.
func TestMixedValidInvalidKeys(t *testing.T) {
	// Generate a valid RSA key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	validN := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	validE := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())

	// Create JWKS with mix of valid and invalid keys
	mixedKeysJWKS := JWKS{
		Keys: []JSONWebKey{
			// Valid key 1
			{
				Kid: "valid-key-1",
				Kty: "RSA",
				N:   validN,
				E:   validE,
				Use: "sig",
			},
			// Invalid: missing N parameter
			{
				Kid: "invalid-missing-n",
				Kty: "RSA",
				E:   validE,
				Use: "sig",
			},
			// Invalid: invalid base64 in E
			{
				Kid: "invalid-base64",
				Kty: "RSA",
				N:   validN,
				E:   "!!!invalid-base64!!!",
				Use: "sig",
			},
			// Valid key 2
			{
				Kid: "valid-key-2",
				Kty: "RSA",
				N:   validN,
				E:   validE,
				Use: "sig",
			},
			// Invalid: unsupported EC key
			{
				Kid: "invalid-ec",
				Kty: "EC",
				Crv: "P-256",
				X:   "test",
				Y:   "test",
			},
			// Invalid: zero value modulus
			{
				Kid: "invalid-zero-modulus",
				Kty: "RSA",
				N:   "AA", // Base64 of 0
				E:   validE,
				Use: "sig",
			},
			// Valid key 3 without 'use' field (should be accepted)
			{
				Kid: "valid-key-3-no-use",
				Kty: "RSA",
				N:   validN,
				E:   validE,
			},
		},
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case openIDConfigurationPath:
			discovery := map[string]string{
				"jwks_uri": r.Host + jwksPath,
			}
			if !strings.HasPrefix(r.Host, "http") {
				discovery["jwks_uri"] = "http://" + discovery["jwks_uri"]
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(discovery); err != nil {
				http.Error(w, "Failed to encode discovery", http.StatusInternalServerError)
			}
		case jwksPath:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(mixedKeysJWKS); err != nil {
				http.Error(w, "Failed to encode JWKS", http.StatusInternalServerError)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Create fetcher
	fetcher, err := NewJWKSFetcher(
		Generic{DiscoveryURL: server.URL + openIDConfigurationPath},
		WithRequireHTTPS(false),
	)
	require.NoError(t, err, "Failed to create fetcher")

	// Start the fetcher to perform initial fetch
	ctx := context.Background()
	err = fetcher.Start(ctx)
	require.NoError(t, err, "Failed to start fetcher")

	// Create validator
	validator := &JWTValidator{
		JWKSFetcher: fetcher,
	}

	// Test that valid keys can be retrieved successfully
	keyFunc := validator.createKeyFunc()

	testCases := []struct {
		kid           string
		shouldSucceed bool
		description   string
	}{
		{"valid-key-1", true, "First valid key should work"},
		{"valid-key-2", true, "Second valid key should work"},
		{"valid-key-3-no-use", true, "Valid key without 'use' field should work"},
		{"invalid-missing-n", false, "Key missing N parameter should fail"},
		{"invalid-base64", false, "Key with invalid base64 should fail"},
		{"invalid-ec", false, "EC key should fail (not supported)"},
		{"invalid-zero-modulus", false, "Key with zero modulus should fail"},
		{"non-existent", false, "Non-existent key should fail"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			// Create a mock token with the kid
			token := &jwtpkg.Token{
				Header: map[string]interface{}{
					"kid": tc.kid,
					"alg": "RS256",
				},
			}

			key, err := keyFunc(token)

			if tc.shouldSucceed {
				assert.NoError(t, err, "Should successfully retrieve key for kid=%s", tc.kid)
				assert.NotNil(t, key, "Retrieved key should not be nil for kid=%s", tc.kid)

				// Verify it's an RSA public key
				rsaKey, ok := key.(*rsa.PublicKey)
				assert.True(t, ok, "Key should be RSA public key for kid=%s", tc.kid)
				assert.NotNil(t, rsaKey, "RSA key should not be nil for kid=%s", tc.kid)
			} else {
				assert.Error(t, err, "Should fail to retrieve key for kid=%s", tc.kid)
				assert.Nil(t, key, "Failed key retrieval should return nil for kid=%s", tc.kid)
			}
		})
	}

	// Verify that the JWKS contains all keys (even invalid ones are stored)
	fetcher.mutex.RLock()
	storedKeys := fetcher.jwks.Keys
	fetcher.mutex.RUnlock()

	assert.Equal(t, 7, len(storedKeys), "All keys should be stored in JWKS, even invalid ones")
}

// TestJWKSLimits tests that JWKS fetching respects both default and custom size/count limits.
func TestJWKSLimits(t *testing.T) {
	tests := []struct {
		name            string
		jwks            JWKS
		options         []Option
		expectedKeys    int
		checkDefaults   bool
		expectedMaxSize int64
		expectedMaxKeys int
	}{
		{
			name: "default limits with single key",
			jwks: JWKS{
				Keys: []JSONWebKey{
					{
						Kid: "key-1",
						Kty: "RSA",
						Use: "sig",
						N:   "test-n",
						E:   "AQAB",
					},
				},
			},
			options:         nil, // Use defaults
			expectedKeys:    1,
			checkDefaults:   true,
			expectedMaxSize: 1 * 1024 * 1024, // 1MB default
			expectedMaxKeys: 100,             // 100 keys default
		},
		{
			name: "custom limits with multiple keys",
			jwks: JWKS{
				Keys: []JSONWebKey{
					{
						Kid: "key-1",
						Kty: "RSA",
						Use: "sig",
						N:   "test-n",
						E:   "AQAB",
					},
					{
						Kid: "key-2",
						Kty: "RSA",
						Use: "sig",
						N:   "test-n-2",
						E:   "AQAB",
					},
				},
			},
			options: []Option{
				WithMaxResponseSize(1024 * 1024), // 1MB
				WithMaxKeysCount(100),
			},
			expectedKeys:    2,
			checkDefaults:   false,
			expectedMaxSize: 1024 * 1024,
			expectedMaxKeys: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up test server
			var serverURL string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case openIDConfigurationPath:
					discovery := map[string]string{
						"jwks_uri": serverURL + "/jwks",
					}
					if err := json.NewEncoder(w).Encode(discovery); err != nil {
						http.Error(w, "Failed to encode discovery response", http.StatusInternalServerError)
						return
					}
				case jwksPath:
					if err := json.NewEncoder(w).Encode(tt.jwks); err != nil {
						http.Error(w, "Failed to encode JWKS response", http.StatusInternalServerError)
						return
					}
				}
			}))
			serverURL = server.URL
			defer server.Close()

			// Create fetcher with specified options
			allOptions := append(tt.options, WithRequireHTTPS(false)) //nolint:gocritic // intentionally creating new slice
			fetcher, err := NewJWKSFetcher(
				Generic{DiscoveryURL: server.URL + "/.well-known/openid-configuration"},
				allOptions...,
			)
			require.NoError(t, err)

			// Check limits if specified
			if tt.checkDefaults {
				assert.Equal(t, tt.expectedMaxSize, fetcher.maxResponseSize, "response size limit mismatch")
				assert.Equal(t, tt.expectedMaxKeys, fetcher.maxKeysCount, "keys count limit mismatch")
			}

			// Fetch should succeed
			jwks, err := fetcher.fetchRemoteJWKS(context.Background(), server.URL+"/jwks")
			assert.NoError(t, err)
			assert.Len(t, jwks.Keys, tt.expectedKeys)

			// Verify first key is always present
			assert.Equal(t, "key-1", jwks.Keys[0].Kid)

			// Verify second key if expected
			if tt.expectedKeys > 1 {
				assert.Equal(t, "key-2", jwks.Keys[1].Kid)
			}
		})
	}
}
