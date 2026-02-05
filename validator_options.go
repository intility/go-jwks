package jwt

import "fmt"

type ValidatorOptions struct {
	issuers      []string
	audiences    []string
	validMethods []string
}

type ValidatorOptionFunc func(*ValidatorOptions) error

// WithIssuers sets any number of allowed issuers.
// Must be used for multi-tenant applications.
// Default is inferred from fetched discovery document
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
