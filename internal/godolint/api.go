package godolint

import (
	"context"
	"log/slog"

	"github.com/farcloser/godolint/sdk"
)

// Violation represents a single linting violation.
type Violation = sdk.Violation

// Severity represents the severity level of a violation.
type Severity = sdk.Severity

// Severity constants.
const (
	SeverityError   = sdk.SeverityError
	SeverityWarning = sdk.SeverityWarning
	SeverityInfo    = sdk.SeverityInfo
	SeverityStyle   = sdk.SeverityStyle
)

// Result aggregates lint results.
type Result struct {
	Violations []Violation
}

// Scanner interface for Dockerfile linting.
type Scanner interface {
	ScanDockerfile(ctx context.Context, dockerfilePath string) (*Result, error)
}

// NewScanner creates a new dockerfile scanner.
func NewScanner(log *slog.Logger) Scanner {
	return &godolintAuditor{
		log: log,
	}
}
