package shared

import "errors"

var (
	// ErrRequirementsFailed indicates that trivy could not be installed.
	ErrRequirementsFailed = errors.New("requirements failed")

	// ErrInvalidArgument indicates the provided image has no tag. User error.
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrCancelled indicates the operation was cancelled via context.
	ErrCancelled = errors.New("operation cancelled")

	// ErrNotFound indicates the source image could not be found.
	ErrNotFound = errors.New("failed to retrieve resource")

	// ErrContext is returned on context error.
	ErrContext = errors.New("context errored")
)
