package derp

import "errors"

var (

	// ErrInvalidEntry indicates an entry is malformed or has invalid data.
	ErrInvalidEntry = errors.New("invalid entry")

	// ErrUnknownEntryType indicates an unrecognized entry type.
	ErrUnknownEntryType = errors.New("unknown entry type")

	// ErrUnsupportedVersion indicates the log version is not supported.
	ErrUnsupportedVersion = errors.New("unsupported version")

	// ErrMissingEntryType indicates the type field is missing from an entry.
	ErrMissingEntryType = errors.New("missing entry type")

	// ErrNotVerified indicates an operation was attempted on unverified data.
	ErrNotVerified = errors.New("log not verified")

	// ErrVerificationFailed indicates cryptographic verification failed.
	ErrVerificationFailed = errors.New("verification failed")

	// ErrInvalidGenesis indicates the genesis entry is invalid or missing.
	ErrInvalidGenesis = errors.New("invalid genesis entry")

	// ErrSignerNotTrusted indicates a signature is from an untrusted signer.
	ErrSignerNotTrusted = errors.New("signer not trusted")

	// ErrSignerRevoked indicates a signer was revoked at the time of signing.
	ErrSignerRevoked = errors.New("signer revoked")

	// ErrNoGenesis indicates no genesis entry was found.
	ErrNoGenesis = errors.New("no genesis entry found")

	// ErrSignerRequired indicates a signer is required but was not provided.
	ErrSignerRequired = errors.New("signer is required")

	// ErrUnsignedCommit indicates a commit is not signed.
	ErrUnsignedCommit = errors.New("commit is not signed")

	// ErrNotAdmin indicates the current signing key is not authorized as admin.
	ErrNotAdmin = errors.New("signing key is not authorized as admin")

	// ErrNotSigner indicates the current signing key is not authorized as signer.
	ErrNotSigner = errors.New("signing key is not authorized as signer")

	// ErrNoSigningKey indicates no signing key was configured.
	ErrNoSigningKey = errors.New("no signing key configured")

	// ErrLogEmpty indicates the log has no entries.
	ErrLogEmpty = errors.New("log is empty")
)
