package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"slices"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("token is invalid")
	ErrInvalidAud   = errors.New("audience is invalid")
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
	keyFunc      jwt.Keyfunc
}

func NewJWTValidator(fetcher *JWKSFetcher, validIssuer string, audiences, validMethods []string) (*JWTValidator, error) {
	if len(validIssuer) == 0 {
		return nil, fmt.Errorf("issuer not configured")
	}

	v := &JWTValidator{
		JWKSFetcher:  fetcher,
		audiences:    audiences,
		validMethods: validMethods,
		validIssuer:  validIssuer,
		logger:       fetcher.logger,
	}

	v.keyFunc = v.createKeyFunc()
	return v, nil
}

// JWTMiddleware takes a JWTValidator and return a function.
// The returned function takes in and returns a http.Handler.
// The returned http.HandlerFunc is the actual middleware.
func JWTMiddleware(validator *JWTValidator) func(http.Handler) http.Handler {
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

			claims, err := validator.ValidateJWT(r.Context(), tokenStr)
			if err != nil {
				// return generic error for security reasons
				http.Error(w, "failed to validate jwt", http.StatusUnauthorized)
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

// The createKeyFunc returns a key lookup function for a given validator.
// A key lookup function accepts a parsed JWT token and returns the corresponing public key
// that was used to sign it, if any is found.
// Also validates that the key is not an encryption key.
func (v *JWTValidator) createKeyFunc() jwt.Keyfunc {
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

// ValidateJWT uses a JWTValidator to validate any standalone JWT.
// Accepts a JWT string and returns any claims specified in the UserClaims struct.
// Returns claims even if there is an error parsing.
func (v *JWTValidator) ValidateJWT(ctx context.Context, tokenStr string) (*UserClaims, error) {
	claims := &UserClaims{}
	// Parse and validate token.
	token, err := jwt.ParseWithClaims(tokenStr, claims, v.keyFunc,
		jwt.WithValidMethods(v.validMethods),
		jwt.WithIssuer(v.validIssuer))
	if err != nil {
		msg := "failed to parse jwt token with claims"
		v.logger.ErrorContext(ctx, msg, "error", err, "iss", claims.Issuer, "valid iss", v.validIssuer)
		return claims, fmt.Errorf("%s: %w", msg, err)
	}

	if !token.Valid {
		msg := "token parsed but is invalid"
		v.logger.ErrorContext(ctx, msg)
		return claims, ErrInvalidToken
	}

	// Check for valid audience
	if !isAudienceValid(claims.Audience, v.audiences) {
		v.logger.ErrorContext(ctx, "token audience validation failed", "audiences", claims.Audience)
		return claims, ErrInvalidAud
	}

	return claims, nil
}

func isAudienceValid(tokenAudience jwt.ClaimStrings, validAudiences []string) bool {
	for _, aud := range tokenAudience {
		if slices.Contains(validAudiences, aud) {
			return true
		}
	}

	return false
}
