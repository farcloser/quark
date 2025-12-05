package trivy

import "errors"

var (
	// ErrParsingFailed indicates trivy output could not be parsed.
	ErrParsingFailed = errors.New("failed to parse trivy output")
	// ErrUnableToLogin indicates trivy was unable to login to the target registry.
	ErrUnableToLogin = errors.New("trivy registry login failed")
	// ErrUnableToScan indicates trivy hard-failed while attempting to scan the image.
	ErrUnableToScan = errors.New("failed to scan")
	// ErrCancelled indicates the scan operation was cancelled via context.
	ErrCancelled = errors.New("scan cancelled")
)
