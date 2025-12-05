package update

import "errors"

// Update errors.
var (
	// ErrCheckUpdateFailed indicates failure to check for updates.
	ErrCheckUpdateFailed = errors.New("failed to check for updates")
)
