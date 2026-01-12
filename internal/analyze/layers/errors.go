package layers

import "errors"

var (
	// ErrAnalysisFailed indicates layer analysis could not complete.
	ErrAnalysisFailed = errors.New("layer analysis failed")

	// ErrInvalidTar indicates the tar stream could not be read.
	ErrInvalidTar = errors.New("invalid tar stream")
)
