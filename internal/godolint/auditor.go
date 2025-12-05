package godolint

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/farcloser/godolint/sdk"
)

// godolintAuditor wraps godolint SDK.
type godolintAuditor struct {
	log *slog.Logger
}

// ScanDockerfile lints a Dockerfile using godolint SDK.
func (auditor *godolintAuditor) ScanDockerfile(ctx context.Context, dockerfilePath string) (*Result, error) {
	auditor.log.InfoContext(ctx, "linting Dockerfile with godolint", "dockerfile", dockerfilePath)

	// Read Dockerfile content
	//nolint:gosec
	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadDockerfile, err)
	}

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

	auditor.log.InfoContext(ctx, "Dockerfile lint complete",
		slog.Int("violations", len(result.Violations)))

	return result, nil
}
