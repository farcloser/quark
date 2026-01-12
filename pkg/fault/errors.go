package fault //revive:disable-line:var-naming

import "errors"

var (
	// ErrSystemFailure for weird conditions like running out of entropy.
	ErrSystemFailure = errors.New("critical system failure")

	// ErrFilesystemFailure covers conditions like failing to open or close a file handler.
	ErrFilesystemFailure = errors.New("filesystem failure")

	// ErrMissingRequirements indicates that a pre-requisite is not / could not be installed.
	ErrMissingRequirements = errors.New("requirements failed")

	// ErrNotImplemented indicates a concrete structs failed to implement a required method.
	ErrNotImplemented = errors.New("not implemented")

	// ErrInvalidArgument indicates the provided argument is invalid.
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrNotFound indicates the requested resource (file, image, etc.) could not be found.
	ErrNotFound = errors.New("failed to retrieve resource")

	// ErrReadFailure indicates the resource (file, image) could not be read (network, filesystem, permission error).
	ErrReadFailure = errors.New("failed to read resource")

	// ErrWriteFailure indicates the resource (file, image) could not be written to (network, filesystem, permission
	// error).
	ErrWriteFailure = errors.New("failed to read resource")

	// ErrAuthenticationFailure indicates an authentication attempt failed.
	ErrAuthenticationFailure = errors.New("failed to authenticate")

	// ErrCancelled indicates the operation was cancelled via context.
	ErrCancelled = errors.New("operation cancelled")

	// ErrContext is returned on context error.
	ErrContext = errors.New("context errored")

	// ErrHashMismatch indicates content hash doesn't match expected digest.
	ErrHashMismatch = errors.New("hash mismatch")

	// ErrInvalidJSON indicates the provided JSON content is not valid, or the provided struct can't be marshalled.
	ErrInvalidJSON = errors.New("invalid JSON")

	// ErrNetworkError indicates we failed to establish a connection.
	ErrNetworkError = errors.New("network error")

	// ErrUnacceptableResponse indicates an http server returned a non-OK response when we expect one.
	ErrUnacceptableResponse = errors.New("unacceptable response")

	// ErrCommandFailure indicates a call to an external binary failed.
	ErrCommandFailure = errors.New("command failed")
)
