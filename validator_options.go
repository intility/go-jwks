package jwt

import (
	"context"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
)

type ValidatorOptions struct {
	issuers      []string
	audiences    []string
	validMethods []string
	// optional user specified claim validators
	claimChecks []func(context.Context, jwt.Claims) error
}

// ValidatorOptionFunc configures ValidatorOptions and may return an error for invalid input.
type ValidatorOptionFunc func(*ValidatorOptions) error

// WithIssuers sets any number of allowed issuers.
// Must be used for multi-tenant applications.
// Default is inferred from fetched discovery document.
func WithIssuers(issuers ...string) ValidatorOptionFunc {
	return func(o *ValidatorOptions) error {
		if len(issuers) == 0 {
			return fmt.Errorf("WithIssuers requires at least one issuer")
		}

		o.issuers = issuers
		return nil
	}
}

// WithAdditionalAudiences appends additional allowed audiences to the required audience.
func WithAdditionalAudiences(audiences ...string) ValidatorOptionFunc {
	return func(o *ValidatorOptions) error {
		if len(audiences) == 0 {
			return fmt.Errorf("WithAdditionalAudiences requires at least one audience")
		}

		o.audiences = append(o.audiences, audiences...)
		return nil
	}
}

// WithValidMethods sets all allowed signing methods.
// Default is RS256.
func WithValidMethods(methods ...string) ValidatorOptionFunc {
	return func(o *ValidatorOptions) error {
		if len(methods) == 0 {
			return fmt.Errorf("WithValidMethods requires at least one method")
		}

		o.validMethods = methods
		return nil
	}
}

// WithClaimValidator registers a type-safe check for claims that are not covered
// by the standard issuer, audience and expiry validation.
//
// Multiple validators run in registration order and the first error fails validation.
//
// Example custom validator:
//
//	WithClaimValidator(func(_ context.Context, c *MyClaims) error {
//		if c.Azp != expectedClientID {
//			return fmt.Errorf("azp %q not allowed", c.Azp)
//		}
//		return nil
//	})
func WithClaimValidator[T jwt.Claims](fn func(ctx context.Context, claims T) error) ValidatorOptionFunc {
	return func(o *ValidatorOptions) error {
		if fn == nil {
			return fmt.Errorf("WithClaimValidator requires a non-nil function")
		}

		// type is evaluated at runtime.
		o.claimChecks = append(o.claimChecks, func(ctx context.Context, c jwt.Claims) error {
			typed, ok := c.(T)
			if !ok {
				return fmt.Errorf("claim validator type mismatch: got %T", c)
			}

			return fn(ctx, typed)
		})

		return nil
	}
}
