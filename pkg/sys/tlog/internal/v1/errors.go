package v1

import "errors"

var (
	// ErrInvalidSigner indicates a signer configuration is invalid.
	ErrInvalidSigner = errors.New("invalid signer configuration")

	// ErrLogEmpty indicates the log has no entries.
	ErrLogEmpty = errors.New("log is empty")

	// errCacheStale indicates the cached state is stale due to history rewrite.
	errCacheStale = errors.New("cache is stale")
)
