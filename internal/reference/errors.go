package reference

import "errors"

var (
	// ErrInvalidImageReference indicates that the image reference is invalid.
	ErrInvalidImageReference = errors.New("invalid image reference")
	// ErrInvalidPattern indicates that the pattern used to parse the image reference is invalid.
	ErrInvalidPattern = errors.New("invalid pattern")
)
