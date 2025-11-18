package secrets

import "errors"

// Common secret errors.
var (
	// ErrUnknownScheme indicates the URI scheme is not recognized.
	ErrUnknownScheme = errors.New("unknown URI scheme")

	// ErrNoBackendRegistered indicates no backend is registered for the scheme.
	ErrNoBackendRegistered = errors.New("no backend registered for scheme")
)

// Generic reference errors (apply to all backends).
var (
	// ErrReferenceEmpty indicates reference is empty.
	ErrReferenceEmpty = errors.New("reference cannot be empty")

	// ErrReferenceInvalidFormat indicates reference has invalid format.
	ErrReferenceInvalidFormat = errors.New("invalid reference format")

	// ErrReferenceEmptyParts indicates reference has empty required components.
	ErrReferenceEmptyParts = errors.New("reference has empty required parts")
)

// Generic field extraction errors (apply to all backends).
var (
	// ErrFieldsEmpty indicates no fields requested for retrieval.
	ErrFieldsEmpty = errors.New("fields list cannot be empty")

	// ErrFieldNotFound indicates requested field not found in secret.
	ErrFieldNotFound = errors.New("field not found in secret")
)

// Generic document errors (apply to all backends).
var (
	// ErrDocumentEmpty indicates document resolved to empty content.
	ErrDocumentEmpty = errors.New("document resolved to empty content")
)

// Generic encryption/decryption errors (apply to encryption-based backends like age, SOPS).
var (
	// ErrFileNotFound indicates encrypted file not found.
	ErrFileNotFound = errors.New("file not found")

	// ErrDecryptionFailed indicates decryption operation failed.
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrInvalidJSON indicates decrypted content is not valid JSON.
	ErrInvalidJSON = errors.New("decrypted content is not valid JSON")

	// ErrIdentityNotSet indicates identity/key environment variable not set.
	ErrIdentityNotSet = errors.New("identity environment variable not set")

	// ErrIdentityNotFound indicates identity/key file not found.
	ErrIdentityNotFound = errors.New("identity file not found")

	// ErrNoMatchingIdentity indicates no identity could decrypt the content.
	ErrNoMatchingIdentity = errors.New("no identity matched (wrong key?)")
)
