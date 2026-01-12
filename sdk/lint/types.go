// Package lint provides Dockerfile linting functionality.
//
// The lint action only collects results (pure augmentation).
// For enforcement decisions, use Builder.Check() with policies.
// For display formatting, use Builder.Log() with log options.
package lint

import (
	"github.com/farcloser/quark/internal/analyze/dockerfile"
)

// This package is kept for backwards compatibility and documentation.
// The actual lint action is implemented in the sdk package.
//
// Migration guide:
//
//	builder.Lint().
//	    Check(policy.Lint{Error: 0}).
//	    Log(&log.Options{LintLevels: log.LintLevelsDefault})

type Severity struct {
	value string
}

// String returns the string representation of the severity.
func (s *Severity) String() string {
	return s.value
}

//nolint:gochecknoglobals // Severity enum pattern requires global variables
var (
	SeverityError   = &Severity{string(dockerfile.SeverityError)}
	SeverityWarning = &Severity{string(dockerfile.SeverityWarning)}
	SeverityInfo    = &Severity{string(dockerfile.SeverityInfo)}
	SeverityStyle   = &Severity{string(dockerfile.SeverityStyle)}
)
