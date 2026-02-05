package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jwtpkg "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// customClaims is a test struct to verify generic claims work end-to-end.
type customClaims struct {
	TenantID string `json:"tenant_id,omitempty"`
	jwtpkg.RegisteredClaims
}

// generateRSAKey creates a new RSA private key.
func generateRSAKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	return privateKey, nil
}

// generateTestJWT creates a JWT for testing.
func generateTestJWT(signingKey *rsa.PrivateKey,
	kid,
	audience string,
	expiry time.Time,
	method jwtpkg.SigningMethod,
	iss string,
) (string, error) {
	token := jwtpkg.New(method)
	token.Header["kid"] = kid
	claims := token.Claims.(jwtpkg.MapClaims)
	claims["aud"] = audience
	claims["exp"] = expiry.Unix()
	claims["iat"] = time.Now().Unix()
	claims["nbf"] = time.Now().Unix()
	claims["iss"] = iss

	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return tokenString, nil
}

// --- Test ---

func TestJWTMiddleware(t *testing.T) {
	//  Generate Keys
	signingKey, err := generateRSAKey()
	assert.NoError(t, err, "Failed to generate signing key")

	invalidSigningKey, err := generateRSAKey()
	assert.NoError(t, err, "Failed to generate invalid signing key")

	// Setup Static JWKS
	kid := "test-kid-12345"
	nBytes := signingKey.N.Bytes()
	nBase64URL := base64.RawURLEncoding.EncodeToString(nBytes)

	eInt := signingKey.E
	eBigInt := big.NewInt(int64(eInt))
	eBytes := eBigInt.Bytes()
	eBase64URL := base64.RawURLEncoding.EncodeToString(eBytes)

	staticJWKS := &JWKS{
		Keys: []JSONWebKey{
			{
				Kid: kid,
				Kty: "RSA",
				// X5c: []string{certX5C}, // Use the base64 encoded certificate DER
				E: eBase64URL,
				// N: "iQ745_U-vjkxPblaw6phBpe08fC42mpcrS4pcr15HiyZQyQV-BFcEVyLwPdsz3ulMRN7OB_UMfCcPBHqOjguejoab6hyJFVVMw_epP4a3SpQN9qaCbnqaSxgSGiqSq663g3TjsF_Wu1m9L41eNoF6Yvh5kULMd6lqjY0LPO5ZZxaQFLtIHahoJKMvYy1BTS0VYcNsXTjxkgUEL6Vc8GV5vaClbnY3VA2hLbXC1SGJWjVGdYXhkuck2tHr58u87MPEaQ33C6YfyISZKsdumF5bTCcIH75jjC3WbMVOLgWg5w0MSiHOFyI76Ihxbb0nRicEuao0WzO9AS7HJ7L24FHFQ",
				N: nBase64URL,
			},
		},
	}

	// Set up a dummy JWKSFetcher with preset keys.
	minimalFetcher := &JWKSFetcher{
		jwks:   staticJWKS,
		mutex:  &sync.RWMutex{},
		logger: slog.Default().With("pkg", "jwks"),
	}

	// Setup Validator.
	audience := "api://my-test-api"
	issuer := "https://auth.example.com"
	validator, err := minimalFetcher.NewJWTValidator(audience, WithIssuers(issuer))
	assert.NoError(t, err, "failed to create validator")

	// Setup Middleware
	jwtMiddleware := JWTMiddleware(validator)

	// Test Handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	testHandler := jwtMiddleware(nextHandler) // Apply middleware

	// --- Test Cases ---
	t.Run("Valid JWT", func(t *testing.T) {
		// Generate a valid JWT token to be used as auth header.
		validToken, err := generateTestJWT(signingKey, kid, audience, time.Now().Add(time.Hour), jwtpkg.SigningMethodRS256, issuer)
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", validToken))
		recorder := httptest.NewRecorder()

		testHandler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code, "Expected status OK for valid token")
		assert.Equal(t, "OK", recorder.Body.String(), "Expected 'OK' body for valid token")
	})

	t.Run("Invalid JWT - Bad Signature", func(t *testing.T) {
		// Generate a token signed with the WRONG key, but using the correct kid
		invalidToken, err := generateTestJWT(invalidSigningKey, kid, audience, time.Now().Add(time.Hour), jwtpkg.SigningMethodRS256, issuer)
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", invalidToken))
		recorder := httptest.NewRecorder()

		testHandler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code, "Expected status Unauthorized for invalid signature")
		assert.Contains(t, recorder.Body.String(), "failed to validate jwt", "Expected generic error message for invalid signature")
	})

	t.Run("Invalid JWT - Wrong Audience", func(t *testing.T) {
		wrongAudToken, err := generateTestJWT(signingKey, kid, "api://wrong-audience", time.Now().Add(time.Hour), jwtpkg.SigningMethodRS256, issuer)
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", wrongAudToken))
		recorder := httptest.NewRecorder()

		testHandler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code, "Expected status Unauthorized for wrong audience")
		assert.Contains(t, recorder.Body.String(), "failed to validate jwt", "Expected generic error message for wrong audience")
	})

	t.Run("Invalid JWT - Expired", func(t *testing.T) {
		// Generate an expired token
		expiredToken, err := generateTestJWT(signingKey, kid, audience, time.Now().Add(-time.Hour), jwtpkg.SigningMethodRS256, issuer) // Expired 1 hour ago
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", expiredToken))
		recorder := httptest.NewRecorder()

		testHandler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code, "Expected status Unauthorized for expired token")
		assert.Contains(t, recorder.Body.String(), "failed to validate jwt", "Expected generic error message for expired token")
	})

	t.Run("Invalid issuer", func(t *testing.T) {
		// Generate a valid JWT token to be used as auth header.
		invalidIss := "https://auth.wrong.com"
		validToken, err := generateTestJWT(signingKey, kid, audience, time.Now().Add(time.Hour), jwtpkg.SigningMethodRS256, invalidIss)
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", validToken))
		recorder := httptest.NewRecorder()

		testHandler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code, "Expected status Unauthorized for invalid issuer")
		assert.Contains(t, recorder.Body.String(), "failed to validate jwt", "Expected generic error message for invalid issuer")
	})

	// Key usage validation tests
	t.Run("Reject encryption key", func(t *testing.T) {
		// Setup fetcher with an encryption key (use:"enc")
		encKeyFetcher := &JWKSFetcher{
			jwks: &JWKS{
				Keys: []JSONWebKey{
					{
						Kid: kid,
						Kty: "RSA",
						Use: "enc", // Encryption key - should be rejected for signing
						E:   eBase64URL,
						N:   nBase64URL,
					},
				},
			},
			mutex:  &sync.RWMutex{},
			logger: slog.Default().With("pkg", "jwks"),
		}

		encValidator, err := encKeyFetcher.NewJWTValidator(audience, WithIssuers(issuer))
		assert.NoError(t, err, "failed to create validator with encryption key")

		encMiddleware := JWTMiddleware(encValidator)
		encHandler := encMiddleware(nextHandler)

		// Generate a valid JWT token
		validToken, err := generateTestJWT(signingKey, kid, audience, time.Now().Add(time.Hour), jwtpkg.SigningMethodRS256, issuer)
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", validToken))
		recorder := httptest.NewRecorder()

		encHandler.ServeHTTP(recorder, req)

		// Should fail because the key is marked for encryption only
		assert.Equal(t, http.StatusUnauthorized, recorder.Code, "Expected status Unauthorized for encryption key")
		assert.Contains(t, recorder.Body.String(), "failed to validate jwt", "Expected generic error message for encryption key")
	})

	t.Run("Accept signature key", func(t *testing.T) {
		// Setup fetcher with a signature key (use:"sig")
		sigKeyFetcher := &JWKSFetcher{
			jwks: &JWKS{
				Keys: []JSONWebKey{
					{
						Kid: kid,
						Kty: "RSA",
						Use: "sig", // Signature key - should be accepted
						E:   eBase64URL,
						N:   nBase64URL,
					},
				},
			},
			mutex:  &sync.RWMutex{},
			logger: slog.Default().With("pkg", "jwks"),
		}

		sigValidator, err := sigKeyFetcher.NewJWTValidator(audience, WithIssuers(issuer))
		assert.NoError(t, err, "failed to create validator with signature key")

		sigMiddleware := JWTMiddleware(sigValidator)
		sigHandler := sigMiddleware(nextHandler)

		// Generate a valid JWT token
		validToken, err := generateTestJWT(signingKey, kid, audience, time.Now().Add(time.Hour), jwtpkg.SigningMethodRS256, issuer)
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", validToken))
		recorder := httptest.NewRecorder()

		sigHandler.ServeHTTP(recorder, req)

		// Should succeed because the key is marked for signatures
		assert.Equal(t, http.StatusOK, recorder.Code, "Expected status OK for signature key")
		assert.Equal(t, "OK", recorder.Body.String(), "Expected 'OK' body for signature key")
	})

	t.Run("Accept key without use field", func(t *testing.T) {
		// The original staticJWKS doesn't have a Use field, so it tests this case
		// Generate a valid JWT token
		validToken, err := generateTestJWT(signingKey, kid, audience, time.Now().Add(time.Hour), jwtpkg.SigningMethodRS256, issuer)
		assert.NoError(t, err)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", validToken))
		recorder := httptest.NewRecorder()

		testHandler.ServeHTTP(recorder, req)

		// Should succeed because keys without use field can be used for any purpose
		assert.Equal(t, http.StatusOK, recorder.Code, "Expected status OK for key without use field")
		assert.Equal(t, "OK", recorder.Body.String(), "Expected 'OK' body for key without use field")
	})
	t.Run("Extract claims from context", func(t *testing.T) {
		validToken, err := generateTestJWT(signingKey, kid, audience, time.Now().Add(time.Hour), jwtpkg.SigningMethodRS256, issuer)
		assert.NoError(t, err)

		// Handler that verifies ClaimsFromContext works
		claimsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := ClaimsFromContext[*UserClaims](r.Context())
			assert.NoError(t, err, "ClaimsFromContext should not return error")
			assert.NotNil(t, claims, "Claims should not be nil")

			// Verify claims contain expected values from the token
			assert.Equal(t, issuer, claims.Issuer, "Issuer should match")
			assert.Contains(t, claims.Audience, audience, "Audience should contain expected value")

			w.WriteHeader(http.StatusOK)
		})

		handler := jwtMiddleware(claimsHandler)

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", validToken))
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code, "Expected status OK")
	})

	t.Run("Custom claims type via generics", func(t *testing.T) {
		// Create validator with custom claims type
		customValidator, err := NewJWTValidatorWithClaims(
			minimalFetcher,
			audience,
			func() *customClaims { return &customClaims{} },
			WithIssuers(issuer),
		)
		assert.NoError(t, err)

		// Generate token with custom tenant_id claim
		token := jwtpkg.New(jwtpkg.SigningMethodRS256)
		token.Header["kid"] = kid
		claims := token.Claims.(jwtpkg.MapClaims)
		claims["aud"] = audience
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["nbf"] = time.Now().Unix()
		claims["iss"] = issuer
		claims["tenant_id"] = "tenant-12345"

		tokenStr, err := token.SignedString(signingKey)
		assert.NoError(t, err)

		// Handler verifies custom claim is accessible
		customHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := ClaimsFromContext[*customClaims](r.Context())
			assert.NoError(t, err)
			assert.Equal(t, "tenant-12345", claims.TenantID, "Custom TenantID should be parsed")
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenStr))
		recorder := httptest.NewRecorder()

		JWTMiddleware(customValidator)(customHandler).ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Code)
	})
}
