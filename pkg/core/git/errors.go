package git

import "errors"

var (
	// Repo errors.

	// ErrNoCommits happens with empty repos.
	ErrNoCommits = errors.New("no commits in repository")
	// ErrNonFastForward indicates the push was rejected.
	ErrNonFastForward = errors.New("non-fast-forward update rejected")

	// Signing.

	// ErrSignatureSigningFailed failed to sign commit.
	ErrSignatureSigningFailed = errors.New("signing failed")

	// Verifications.

	// ErrSignatureVerificationFailed failed to verify commit.
	ErrSignatureVerificationFailed = errors.New("failed to verify git signature")

	// ErrSignatureNoSuchCommit indicates either a missing commit, or something really wrong with the repo.
	ErrSignatureNoSuchCommit = errors.New("unable to read commit")
	// ErrSignatureMissing indicates the commit has no signature (returned only by Verify).
	ErrSignatureMissing = errors.New("commit has no signature")
	// ErrSignatureInvalidFormat indicates the signature format is unsupported or more likely that signature is hosed.
	ErrSignatureInvalidFormat = errors.New("invalid signature format")

	// buildCommitContent.

	// ErrSignatureCommitError failure to encode commit.
	ErrSignatureCommitError = errors.New("encode commit")

	// dearmorSSHSignature.

	// ErrSignatureMissingBeginMarker indicates a hosed signature.
	ErrSignatureMissingBeginMarker = errors.New("missing BEGIN marker")
	// ErrSignatureMissingEndMarker indicates a hosed signature.
	ErrSignatureMissingEndMarker = errors.New("missing END marker")
	// ErrSignatureMalformedArmor indicates a hosed signature.
	ErrSignatureMalformedArmor = errors.New("malformed armor: END before BEGIN")
	// ErrSignatureMalformedB64 indicates a hosed signature.
	ErrSignatureMalformedB64 = errors.New("malformed base64")

	// parseSSHSignatureBlob errors.

	// ErrSignatureInvalidMagic indicates a hosed signature.
	ErrSignatureInvalidMagic = errors.New("invalid magic")
	// ErrSignatureUnsupportedVersion indicates a hosed signature.
	ErrSignatureUnsupportedVersion = errors.New("unsupported version")
	// ErrSignatureParsePublicKey indicates a hosed signature.
	ErrSignatureParsePublicKey = errors.New("failed to parse public key")
	// ErrSignatureParseSig indicates a hosed signature.
	ErrSignatureParseSig = errors.New("failed to parse signature")
	// ErrSignatureUnsupportedHash indicates a hosed signature.
	ErrSignatureUnsupportedHash = errors.New("unsupported hash algorithm")

	// readSSHString errors.

	// ErrSignatureStringTooLong indicates a malevolent signature.
	ErrSignatureStringTooLong = errors.New("string field exceeds maximum length")
)
