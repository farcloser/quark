package lint

import "errors"

// Lint errors.
var (
	// ErrLintFailed indicates the dockerfile lint operation failed.
	ErrLintFailed = errors.New("dockerfile lint failed")

	// ErrArgumentInvalidSeverity indicates an invalid severity value.
	ErrArgumentInvalidSeverity = errors.New("invalid severity")

	// ErrFormatOutput indicates output formatting failed.
	ErrFormatOutput = errors.New("failed to format output")
)
