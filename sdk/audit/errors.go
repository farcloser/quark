package audit

import "errors"

// Audit errors.
var (
	// ErrArgumentRequiredImageDigest indicates image digest is required.
	ErrArgumentRequiredImageDigest = errors.New("requires the image to have a digest")

	// ErrArgumentInvalidLevel indicates an invalid level value.
	ErrArgumentInvalidLevel = errors.New("invalid level")

	// ErrRequirementsFailed if dockle cannot be installed.
	ErrRequirementsFailed = errors.New("missing dependency")

	// ErrScanFailed if failing to scan.
	ErrScanFailed = errors.New("failed to scan platform")

	// ErrVulnerable indicates vulnerabilities were found at or above threshold.
	ErrVulnerable = errors.New("image is vulnerable at or above threshold")

	// ErrFormatOutput indicates output formatting failed.
	ErrFormatOutput = errors.New("failed to format output")
)
