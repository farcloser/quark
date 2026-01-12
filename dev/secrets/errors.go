package secrets

import (
	"errors"
)

// Generic document errors (apply to all backends).
var (
	// ErrDocumentEmpty indicates document resolved to empty content.
	ErrDocumentEmpty = errors.New("document resolved to empty content")
)
