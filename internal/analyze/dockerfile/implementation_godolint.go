package dockerfile

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/godolint/sdk"
)

// godolintAuditor wraps godolint SDK.
type godolintAuditor struct {
	log *slog.Logger
}

// ScanDockerfile lints Dockerfile content using godolint SDK.
func (auditor *godolintAuditor) Scan(ctx context.Context, content []byte) (*Result, error) {
	auditor.log.DebugContext(ctx, "linting dockerfile content")

	// Create linter and run
	linter := sdk.New()

	lintResult, err := linter.Lint(ctx, content)
	if err != nil {
		auditor.log.ErrorContext(ctx, "godolint linting failed", "error", err)

		return nil, fmt.Errorf("%w: %w", ErrLintFailed, err)
	}

	result := &Result{
		Violations: lintResult.Violations,
	}

	auditor.log.DebugContext(ctx, "Dockerfile lint complete",
		slog.Int("violations", len(result.Violations)))

	return result, nil
}
