package config

import "errors"

var (
	// ErrInvalidConfig indicates the config blob could not be parsed.
	ErrInvalidConfig = errors.New("invalid image config")

	// ErrAnalysisFailed indicates analysis could not complete.
	ErrAnalysisFailed = errors.New("config analysis failed")
)
