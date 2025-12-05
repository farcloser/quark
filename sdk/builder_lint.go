package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/godolint"
	"github.com/farcloser/quark/sdk/lint"
)

const (
	msgLintIssuesFound = "lint issues found matching severity filter"
)

type buildLintAction struct {
	resource.BaseResource[buildLintAction]

	log     *slog.Logger
	builder *Builder
	opts    *lint.Options
	result  *godolint.Result
}

// Execute performs the Dockerfile lint using godolint.
func (la *buildLintAction) Execute(ctx context.Context) error {
	dockerfilePath := la.builder.opts.Dockerfile

	if la.opts == nil {
		la.opts = &lint.Options{}
	}

	if la.opts.Format == nil {
		la.opts.Format = lint.FormatTable
	}

	if la.opts.SeverityChecks == nil {
		la.opts.SeverityChecks = lint.SetSeverityCheckRecommended
	}

	// Run lint
	scanner := godolint.NewScanner(la.log)

	result, err := scanner.ScanDockerfile(ctx, dockerfilePath)
	if err != nil {
		return fmt.Errorf("%w: %w", lint.ErrLintFailed, err)
	}

	for _, check := range la.opts.SeverityChecks {
		// Skip if no severities specified
		if len(check.Severities) == 0 {
			la.log.Warn("no severities set for severity check, ignoring")

			continue
		}

		matchingViolations := la.getViolationsBySeverities(result, check.Severities, la.opts.Ignore)
		if len(matchingViolations) == 0 {
			continue // No violations matching these severities, skip
		}

		// Format output for matching violations
		output, err := la.FormatOutput(matchingViolations, la.opts.Format)
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		// Handle according to action (default to error if not specified)
		action := check.Action
		if action == nil {
			action = lint.ActionError
		}

		severitiesStr := lintSeveritiesToString(check.Severities)

		switch action { //revive:disable-line:enforce-switch-style
		case lint.ActionError:
			la.log.Error(msgLintIssuesFound,
				slog.String("severities", severitiesStr),
				slog.Int("count", len(matchingViolations)),
			)
			la.log.Error(output)

			return fmt.Errorf("%w: %s", lint.ErrLintFailed, severitiesStr)

		case lint.ActionWarn:
			la.log.Warn(msgLintIssuesFound,
				slog.String("severities", severitiesStr),
				slog.Int("count", len(matchingViolations)),
			)
			la.log.Warn(output)

		case lint.ActionInfo:
			la.log.Info(msgLintIssuesFound,
				slog.String("severities", severitiesStr),
				slog.Int("count", len(matchingViolations)),
			)
			la.log.Info(output)

		case lint.ActionDebug:
			la.log.Debug(msgLintIssuesFound,
				slog.String("severities", severitiesStr),
				slog.Int("count", len(matchingViolations)),
			)
			la.log.Debug(output)
		}
	}

	la.result = result

	return nil
}

// lintSeveritiesToString converts a slice of severities to a comma-separated string.
func lintSeveritiesToString(severities []*lint.Severity) string {
	strs := make([]string, len(severities))
	for i, sev := range severities {
		strs[i] = sev.String()
	}

	return strings.Join(strs, ",")
}

// FormatOutput formats lint results for display.
func (*buildLintAction) FormatOutput(violations []godolint.Violation, format *lint.Format) (string, error) {
	switch format {
	case lint.FormatTable:
		return formatLintTable(violations), nil
	case lint.FormatJSON:
		bytes, err := json.MarshalIndent(violations, "", "  ")
		if err != nil {
			return "", err
		}

		return string(bytes), nil
	default:
		// case lint.FormatSARIF:
		panic("not implemented")
	}
}

// getViolationsBySeverities returns violations matching any of the specified severities.
func (*buildLintAction) getViolationsBySeverities(
	result *godolint.Result,
	severities []*lint.Severity,
	ignore []string,
) []godolint.Violation {
	// Build a set of severity strings for O(1) lookup
	severitySet := make(map[string]struct{}, len(severities))
	for _, sev := range severities {
		severitySet[sev.String()] = struct{}{}
	}

	// Build a set of ignored rule codes for O(1) lookup
	ignoreSet := make(map[string]struct{}, len(ignore))
	for _, code := range ignore {
		ignoreSet[code] = struct{}{}
	}

	var matching []godolint.Violation

	for _, violation := range result.Violations {
		// Skip if rule code is in ignore list
		if _, ignored := ignoreSet[violation.Code]; ignored {
			continue
		}

		if _, ok := severitySet[string(violation.Severity)]; ok {
			matching = append(matching, violation)
		}
	}

	return matching
}

func formatLintTable(violations []godolint.Violation) string {
	if len(violations) == 0 {
		return "No Dockerfile issues found\n"
	}

	var builder strings.Builder

	_, _ = builder.WriteString("DOCKERFILE LINT RESULTS\n")
	_, _ = builder.WriteString(strings.Repeat("=", 80) + "\n\n")

	for _, violation := range violations {
		_, _ = builder.WriteString(fmt.Sprintf(
			"[%s] Line %d: %s\n",
			violation.Severity,
			violation.Line,
			violation.Code,
		))
		_, _ = builder.WriteString(fmt.Sprintf("  %s\n\n", violation.Message))
	}

	_, _ = builder.WriteString(strings.Repeat("=", 80) + "\n")
	_, _ = builder.WriteString(fmt.Sprintf("Total issues: %d\n", len(violations)))

	return builder.String()
}
