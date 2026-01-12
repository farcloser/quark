package audit

import "errors"

// Audit errors.
var (
	// ErrArgumentRequiredImageDigest indicates image digest is required.
	ErrArgumentRequiredImageDigest = errors.New("requires the image to have a digest")

	// ErrArgumentInvalidLevel indicates an invalid level value.
	ErrArgumentInvalidLevel = errors.New("invalid level")

	// ErrScanFailed if failing to scan.
	ErrScanFailed = errors.New("failed to scan platform")
)
