package sdk

import (
	"context"
	"fmt"
	"os"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/analyze/dockerfile"
	"github.com/farcloser/quark/sdk/lint"
)

type lintAction struct {
	*resource.BaseAction

	builder *Builder
	output  *Builder
}

func (la *lintAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(la, la.BaseAction, name, out, copyFrom...)
}

// Execute performs the Dockerfile lint using godolint.
// This is pure augmentation - it only populates results on the builder.
// Use Check() with a policy for enforcement and Log() for display.
func (la *lintAction) Execute(ctx context.Context) error {
	logger := la.output.log
	output := la.output

	dockerfilePath := la.builder.options.Dockerfile

	// Read Dockerfile content
	//nolint:gosec // File path comes from user configuration
	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return fmt.Errorf("%w: %w", lint.ErrReadDockerfile, err)
	}

	// Run lint
	scanner := dockerfile.NewScanner(output.log)

	result, err := scanner.Scan(ctx, content)
	if err != nil {
		return fmt.Errorf("%w: %w", lint.ErrLintFailed, err)
	}

	// Store result for later use by Check() and Log()
	output.lintResult = result

	logger.DebugContext(ctx, "lint executed")

	return nil
}
