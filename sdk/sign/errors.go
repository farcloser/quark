package sign

import "errors"

// Sign errors.
var (
	// ErrArgumentRequiredImageDigest indicates image digest is required.
	ErrArgumentRequiredImageDigest = errors.New("requires the image to have a digest")

	// ErrArgumentRequiredSigner indicates a signer is required.
	ErrArgumentRequiredSigner = errors.New("requires a signer")

	// ErrSigningFailed indicates the signing operation failed.
	ErrSigningFailed = errors.New("signing failed")
)
