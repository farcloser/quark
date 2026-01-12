package sdk

import (
	"context"
	"fmt"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/a_deprecated/dockle"
	"github.com/farcloser/quark/sdk/audit"
)

type auditAction struct {
	*resource.BaseAction

	opts   *audit.Options
	output *Image
}

func (aa *auditAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(aa, aa.BaseAction, name, out, copyFrom...)
}

func (aa *auditAction) Execute(ctx context.Context) error {
	output := aa.output

	// Audit can only scan by digest. Fail first if digest is NOT set
	if output.ref.Digest == "" {
		return fmt.Errorf("%w: %s", audit.ErrArgumentRequiredImageDigest, output.ref.String())
	}

	tag := output.ref.Tag
	output.ref.Tag = ""

	if aa.opts == nil {
		aa.opts = &audit.Options{}
	}

	// Create dockle scanner
	scanner, err := dockle.NewScanner(ctx, output.log)
	if err != nil {
		return fmt.Errorf("%w: %w", fault.ErrMissingRequirements, err)
	}

	// Filter ignored checks from result
	result, err := scanner.ScanImage(
		ctx,
		output.ref.String(),
		output.registry.credentials(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", audit.ErrScanFailed, err)
	}

	// Apply ignore filter if specified
	if len(aa.opts.Ignore) > 0 {
		result = filterIgnoredChecks(result, aa.opts.Ignore)
	}

	// Attach results to output image for downstream processing
	aa.output.auditResult = result

	output.ref.Tag = tag

	return nil
}

// filterIgnoredChecks removes details with codes in the ignore list.
func filterIgnoredChecks(result *dockle.ScanResult, ignore []string) *dockle.ScanResult {
	ignoreSet := make(map[string]struct{}, len(ignore))
	for _, code := range ignore {
		ignoreSet[code] = struct{}{}
	}

	filtered := make([]dockle.Detail, 0, len(result.Details))

	for _, detail := range result.Details {
		if _, ignored := ignoreSet[detail.Code]; !ignored {
			filtered = append(filtered, detail)
		}
	}

	return &dockle.ScanResult{
		Details: filtered,
	}
}
