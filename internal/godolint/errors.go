package godolint

import "errors"

var (
	// ErrReadDockerfile indicates the Dockerfile could not be read.
	ErrReadDockerfile = errors.New("failed to read Dockerfile")
	// ErrLintFailed indicates the godolint linting operation failed.
	ErrLintFailed = errors.New("godolint linting failed")
)
