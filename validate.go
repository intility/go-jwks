package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"slices"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	BearerSchema   = "Bearer"
	authHeaderPart = 2
)

type JWKS struct {
	Keys []JSONWebKey `json:"keys"`
}
type JSONWebKey struct {
	Kid string `json:"kid"`           // Key ID - required
	Kty string `json:"kty"`           // Key Type - Required
	Use string `json:"use,omitempty"` // Key Use
	Alg string `json:"alg,omitempty"` // Algorithm

	// RSA-specific parameters
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Public Exponent

	// EC-specific parameters
	Crv string `json:"crv,omitempty"` // Curve - e.g. P-256
	X   string `json:"x,omitempty"`   // X Coordinate
	Y   string `json:"y,omitempty"`   // Y Coordinate

	// X.509 Certificate Chain
	X5c []string `json:"x5c,omitempty"` // Can be used as fallback or primary source
}

type JWTValidator struct {
	JWKSFetcher  *JWKSFetcher
	audiences    []string
	validMethods []string
	validIssuer  string
	logger       *slog.Logger
}

func NewJWTValidator(fetcher *JWKSFetcher, validIssuer string, audiences, validMethods []string) (*JWTValidator, error) {
	if len(validIssuer) == 0 {
		return nil, fmt.Errorf("issuer not configured")
	}

	return &JWTValidator{
		JWKSFetcher:  fetcher,
		audiences:    audiences,
		validMethods: validMethods,
		validIssuer:  validIssuer,
		logger:       fetcher.logger,
	}, nil
}

// JWTMiddleware takes a JWTValidator and return a function.
// The returned function takes in and returns a http.Handler.
// The returned http.HandlerFunc is the actual middleware.
func JWTMiddleware(validator *JWTValidator) func(http.Handler) http.Handler {
	keyFunc := validator.createKeyFunc()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")

			if authHeader == "" {
				validator.logger.ErrorContext(r.Context(), "received request with no auth header")
				http.Error(w, "auth header missing", http.StatusUnauthorized)
				return
			}
			parts := strings.SplitN(authHeader, " ", authHeaderPart)
			if len(parts) != authHeaderPart || parts[0] != BearerSchema {
				validator.logger.ErrorContext(r.Context(), "received request with malformed auth header")
				http.Error(w, "bad auth header format", http.StatusBadRequest)
				return
			}

			tokenStr := parts[1]

			claims := &UserClaims{}

			// Parse and validate token.
			token, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc,
				jwt.WithValidMethods(validator.validMethods),
				jwt.WithIssuer(validator.validIssuer))
			if err != nil {
				msg := "failed to parse jwt token with claims"
				validator.logger.ErrorContext(r.Context(), msg, "error", err, "iss", claims.Issuer, "valid iss", validator.validIssuer)
				http.Error(w, msg, http.StatusUnauthorized)
				return
			}

			if !token.Valid {
				msg := "token parsed but is invalid"
				slog.ErrorContext(r.Context(), msg)
				http.Error(w, msg, http.StatusUnauthorized)
				return
			}

			// Check for valid audience
			validAud := false
			tokenAudience := claims.Audience

			// Single aud
			if len(tokenAudience) == 1 {
				if slices.Contains(validator.audiences, tokenAudience[0]) {
					validAud = true
				}
				// multiple auds
			} else {
				for _, aud := range tokenAudience {
					if slices.Contains(validator.audiences, aud) {
						validAud = true
						break
					}
				}
			}

			if !validAud {
				validator.logger.ErrorContext(r.Context(), "token audience validation failed", "audiences", claims.Audience)
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			// Add claims to context.
			ctx := context.WithValue(r.Context(), userClaimsKey, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Parse JWK. Attempt both RSA and EC parsing. Return the constructed public key.
func parseKey(jwk *JSONWebKey) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		if jwk.N != "" && jwk.E != "" {
			// Construct public key from RSA params.
			nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
			if err != nil {
				return nil, fmt.Errorf("failed to decode RSA modulus 'n': %w", err)
			}
			n := new(big.Int).SetBytes(nBytes)
			eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
			if err != nil {
				return nil, fmt.Errorf("failed to decode RSA modulus 'e': %w", err)
			}

			e := new(big.Int).SetBytes(eBytes)
			if n.BitLen() == 0 || e.BitLen() == 0 {
				return nil, fmt.Errorf("RSA modulus or exponent resulted in zero value")
			}

			// Check if e is to big for convert
			if !e.IsInt64() {
				return nil, fmt.Errorf("RSA exponent 'e' is too big to fit in an int")
			}

			return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
		} else {
			return nil, fmt.Errorf("missing N and/or E param")
		}
	case "EC":
		// TODO: add EC support
		// Extract eclipse params and construct public key
		return nil, fmt.Errorf("EC not yet supported")
	default:
		return nil, fmt.Errorf("method not supported: %s", jwk.Kty)
	}
}

// Returns a key lookup function function that takes in a jwt token
// and returns the corresponding public key if a matching key id is found in the store.
// Also validates that the key is not an encryption key.
func (v *JWTValidator) createKeyFunc() func(*jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("no kid in claim")
		}

		// Lock and read from jwks store.
		v.JWKSFetcher.mutex.RLock()
		defer v.JWKSFetcher.mutex.RUnlock()

		if v.JWKSFetcher.jwks == nil {
			return nil, fmt.Errorf("no keys have been fetched (initial fetch pending or failed)")
		}

		// Check if any of the public keys IDs match the auth header kid.
		// If match, parse and return corresponding public key.
		for _, key := range v.JWKSFetcher.jwks.Keys {
			if key.Kid == kid {
				// Validate key usage - only allow keys with use:"sig" or no use specified
				// Reject keys explicitly marked for encryption only (use:"enc")
				if key.Use != "" && key.Use != "sig" {
					v.logger.Error("key usage validation failed", "kid", kid, "use", key.Use)
					return nil, fmt.Errorf("key %s has invalid use '%s' for signature verification", kid, key.Use)
				}

				pubkey, err := parseKey(&key)
				if err != nil {
					v.logger.Error("failed to parse public key from JWK", "error", err)
					return nil, fmt.Errorf("failed to parse key for kid %s: %w", kid, err)
				}
				if pubkey == nil {
					return nil, fmt.Errorf("key found for kid %s, but parsing resulted in nil key", key)
				}
				return pubkey, nil
			}
		}
		return nil, fmt.Errorf("signing key not found")
	}
}
