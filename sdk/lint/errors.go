package lint

import "errors"

// Lint errors.
var (
	// ErrLintFailed indicates the dockerfile lint operation failed.
	ErrLintFailed = errors.New("dockerfile lint failed")

	// ErrArgumentInvalidSeverity indicates an invalid severity value.
	ErrArgumentInvalidSeverity = errors.New("invalid severity")
)
