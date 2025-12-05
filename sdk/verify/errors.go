package verify

import "errors"

// Verify errors.
var (
	// ErrGetDigest indicates failure to retrieve image digest from registry.
	ErrGetDigest = errors.New("failed to get image digest")

	// ErrSignatureVerificationFailed indicates the signature failed cryptographic verification.
	ErrSignatureVerificationFailed = errors.New("signature verification failed")

	// ErrSignerNotTrusted indicates the signer identity doesn't match any trusted identity.
	ErrSignerNotTrusted = errors.New("signer not trusted")

	// ErrNoTrustedIdentities indicates no trusted identities were configured for keyless verification.
	ErrNoTrustedIdentities = errors.New("no trusted identities configured")
)
