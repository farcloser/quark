package sync

import "errors"

// Sync errors.
var (
	// ErrArgumentRequiredImageDigest indicates image digest is required.
	ErrArgumentRequiredImageDigest = errors.New("requires the image to have a digest")

	// ErrArgumentRequiredDestination indicates a destination has not been provided.
	ErrArgumentRequiredDestination = errors.New("requires a destination image")

	// ErrSyncFailed is failing to sync.
	ErrSyncFailed = errors.New("failed to sync image")
)
