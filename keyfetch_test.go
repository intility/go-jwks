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
				json.NewEncoder(w).Encode(discovery)
			case "/jwks":
				// Return JWKS
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(jwks)
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
			json.NewEncoder(w).Encode(discovery)
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
				json.NewEncoder(w).Encode(discovery)
			case "/jwks":
				// Return JWKS
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(jwks)
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
