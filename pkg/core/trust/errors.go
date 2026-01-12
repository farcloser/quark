package trust

import "errors"

var (
	// ErrPEMDecodeFailed happens if we cant decode a PEM.
	ErrPEMDecodeFailed = errors.New("unable to decode PEM")
	// ErrParsePublicKeyFailed happens if PEM decode succeeded, but we just cannot parse the result.
	ErrParsePublicKeyFailed = errors.New("unable to parse public key")
	// ErrUnknownKeyType happens for unsupported PEM file types.
	ErrUnknownKeyType = errors.New("unknown public key PEM file type")
	// ErrFailedToMarshal happens if we fail marshalling a public key.
	ErrFailedToMarshal = errors.New("unable to marshal public key")
	// ErrEmptyKey if provided key is empty...
	ErrEmptyKey = errors.New("no public key found")
)
