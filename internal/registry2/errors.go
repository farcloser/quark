package registry2

import "errors"

var (
	// ErrForbidden is returned when credentials are valid but access is denied (HTTP 403).
	ErrForbidden = errors.New("forbidden")

	// ErrRegistryError is returned for unexpected registry errors.
	ErrRegistryError = errors.New("registry error")

	// ErrRegistryOperationFailed is returned when a registry operation fails.
	ErrRegistryOperationFailed = errors.New("registry operation failed")
)
