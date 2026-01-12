package logger

import "errors"

// Sentinel errors for log operations.
var (
	// ErrNoResults is returned when attempting to log with no scan or audit results available.
	ErrNoResults = errors.New("no scan or audit results to log")

	// ErrFormatOutput is returned when output formatting fails.
	ErrFormatOutput = errors.New("failed to format output")
)
