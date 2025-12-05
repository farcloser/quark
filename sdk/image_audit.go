package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/dockle"
	"github.com/farcloser/quark/sdk/audit"
)

const (
	msgIssuesFound = "issues found matching level filter"
)

type auditAction struct {
	resource.BaseResource[auditAction]

	log    *slog.Logger
	opts   *audit.Options
	image  *Image
	result *dockle.ScanResult
}

func (aa *auditAction) Execute(ctx context.Context) error {
	// Audit can only scan by digest. Fail first if digest is NOT set
	if aa.image.ref.Digest == "" {
		return fmt.Errorf("%w: %s", audit.ErrArgumentRequiredImageDigest, aa.image.ref.String())
	}

	if aa.opts == nil {
		aa.opts = &audit.Options{}
	}

	if aa.opts.Format == nil {
		aa.opts.Format = audit.FormatTable
	}

	if aa.opts.SeverityChecks == nil {
		aa.opts.SeverityChecks = audit.SetSeverityCheckRecommended
	}

	// Create dockle scanner
	scanner, err := dockle.NewScanner(ctx, aa.log)
	if err != nil {
		return fmt.Errorf("%w: %w", audit.ErrRequirementsFailed, err)
	}

	result, err := scanner.ScanImage(
		ctx,
		aa.image.ref.String(),
		aa.image.registry.credentials(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", audit.ErrScanFailed, err)
	}

	for _, check := range aa.opts.SeverityChecks {
		// Skip if no levels specified
		if len(check.Levels) == 0 {
			aa.log.Warn("no levels set for level check, ignoring")

			continue
		}

		matchingDetails := aa.getDetailsByLevels(result, check.Levels, aa.opts.Ignore)
		if len(matchingDetails) == 0 {
			continue // No issues matching these levels, skip
		}

		// Format output for matching issues
		matchingResult := &dockle.ScanResult{
			Details: matchingDetails,
		}

		output, err := aa.FormatOutput(matchingResult, aa.opts.Format)
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		// Handle according to action (default to error if not specified)
		action := check.Action
		if action == nil {
			action = audit.ActionError
		}

		levelsStr := levelsToString(check.Levels)

		switch action { //revive:disable-line:enforce-switch-style
		case audit.ActionError:
			aa.log.Error(msgIssuesFound,
				slog.String("levels", levelsStr),
				slog.Int("count", len(matchingDetails)),
			)
			aa.log.Error(output)

			return fmt.Errorf("%w: %s", audit.ErrVulnerable, levelsStr)

		case audit.ActionWarn:
			aa.log.Warn(msgIssuesFound,
				slog.String("levels", levelsStr),
				slog.Int("count", len(matchingDetails)),
			)
			aa.log.Warn(output)

		case audit.ActionInfo:
			aa.log.Info(msgIssuesFound,
				slog.String("levels", levelsStr),
				slog.Int("count", len(matchingDetails)),
			)
			aa.log.Info(output)

		case audit.ActionDebug:
			aa.log.Debug(msgIssuesFound,
				slog.String("levels", levelsStr),
				slog.Int("count", len(matchingDetails)),
			)
			aa.log.Debug(output)
		}
	}

	aa.result = result

	return nil
}

// levelsToString converts a slice of levels to a comma-separated string.
func levelsToString(levels []*audit.Severity) string {
	strs := make([]string, len(levels))
	for i, lvl := range levels {
		strs[i] = lvl.String()
	}

	return strings.Join(strs, ",")
}

// FormatOutput formats audit results for display.
func (*auditAction) FormatOutput(result *dockle.ScanResult, format *audit.Format) (string, error) {
	switch format {
	case audit.FormatTable:
		return formatAuditTable(result), nil
	case audit.FormatJSON:
		bytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", fmt.Errorf("%w: %w", audit.ErrFormatOutput, err)
		}

		return string(bytes), nil
	default:
		// case audit.FormatSARIF:
		panic("not implemented")
	}
}

// getDetailsByLevels returns details matching any of the specified levels,
// excluding any check codes in the ignore list.
func (*auditAction) getDetailsByLevels(
	result *dockle.ScanResult,
	levels []*audit.Severity,
	ignore []string,
) []dockle.Detail {
	// Build a set of level strings for O(1) lookup
	levelSet := make(map[string]struct{}, len(levels))
	for _, lvl := range levels {
		levelSet[lvl.String()] = struct{}{}
	}

	// Build a set of ignored check codes for O(1) lookup
	ignoreSet := make(map[string]struct{}, len(ignore))
	for _, code := range ignore {
		ignoreSet[code] = struct{}{}
	}

	var matching []dockle.Detail

	for _, detail := range result.Details {
		// Skip if check code is in ignore list
		if _, ignored := ignoreSet[detail.Code]; ignored {
			continue
		}

		if _, ok := levelSet[detail.Level]; ok {
			matching = append(matching, detail)
		}
	}

	return matching
}

func formatAuditTable(result *dockle.ScanResult) string {
	if len(result.Details) == 0 {
		return "No image issues found\n"
	}

	var builder strings.Builder

	_, _ = builder.WriteString("IMAGE AUDIT RESULTS\n")
	_, _ = builder.WriteString(strings.Repeat("=", 80) + "\n\n")

	for _, detail := range result.Details {
		_, _ = builder.WriteString(fmt.Sprintf(
			"[%s] %s - %s\n",
			detail.Level,
			detail.Code,
			detail.Title,
		))

		for _, alert := range detail.Alerts {
			_, _ = builder.WriteString(fmt.Sprintf("  - %s\n", alert))
		}

		_, _ = builder.WriteString("\n")
	}

	_, _ = builder.WriteString(strings.Repeat("=", 80) + "\n")
	_, _ = builder.WriteString(fmt.Sprintf("Total issues: %d\n", len(result.Details)))

	return builder.String()
}
