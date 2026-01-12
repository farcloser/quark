package scan

import "errors"

// Scan errors.
var (
	// ErrArgumentRequiredImageDigest indicates image digest is required.
	ErrArgumentRequiredImageDigest = errors.New("requires the image to have a digest")

	// ErrScanFailed if failing to scan.
	ErrScanFailed = errors.New("failed to scan platform")
)
