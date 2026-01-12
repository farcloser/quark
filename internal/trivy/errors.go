package trivy

import "errors"

var (
	// ErrParsingFailed indicates trivy output could not be parsed.
	ErrParsingFailed = errors.New("failed to parse trivy output")
	// ErrUnableToScan indicates trivy hard-failed while attempting to scan the image.
	ErrUnableToScan = errors.New("failed to scan")
)
