package layers

import (
	"context"
	"io"
)

// Result aggregates layer scan results.
type Result struct {
	Assessments []*Assessment
}

// Scanner interface for OCI image layer analysis.
type Scanner interface {
	Scan(ctx context.Context, layers []io.Reader) (*Result, error)
}

// NewScanner creates a new layer scanner using the native implementation.
func NewScanner(opts Options) Scanner {
	return newNativeScanner(opts)
}
