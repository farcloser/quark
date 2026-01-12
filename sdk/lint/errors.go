package lint

import "errors"

// Lint errors.
var (
	// ErrReadDockerfile indicates the Dockerfile could not be read.
	ErrReadDockerfile = errors.New("failed to read Dockerfile")
	// ErrLintFailed indicates the dockerfile lint operation failed.
	ErrLintFailed = errors.New("dockerfile lint failed")
)
