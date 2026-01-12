package build

import "errors"

// Build errors.
var (
	// ErrNodeRequired indicates a build node is required.
	ErrNodeRequired = errors.New("build node is required")

	// ErrBuildFailed indicates the build operation failed.
	ErrBuildFailed = errors.New("build failed")
)
