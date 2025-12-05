package audit

import "errors"

// Scan errors.
var (
	// ErrArgumentRequiredImageDigest indicates image digest is required.
	ErrArgumentRequiredImageDigest = errors.New("requires the image to have a digest")

	// ErrArgumentInvalidLevel indicates an invalid level value.
	ErrArgumentInvalidLevel = errors.New("invalid level")

	// ErrRequirementsFailed if trivy cannot be installed.
	ErrRequirementsFailed = errors.New("missing dependency")

	// ErrScanFailed if failing to scan.
	ErrScanFailed = errors.New("failed to scan platform")

	// ErrVulnerable indicates vulnerabilities were found at or above threshold.
	ErrVulnerable = errors.New("image is vulnerable at or above threshold")
)
