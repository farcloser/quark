package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	devformat "github.com/farcloser/quark/dev/format"
	"github.com/farcloser/quark/dev/resource"
	godolint2 "github.com/farcloser/quark/internal/analyze/dockerfile"
	"github.com/farcloser/quark/sdk/lint"
	sdklog "github.com/farcloser/quark/sdk/logger"
)

type builderLogAction struct {
	*resource.BaseAction

	opts   *sdklog.Options
	output *Builder
}

func (la *builderLogAction) AddOutput(
	name string,
	out resource.Resource,
	copyFrom ...resource.Resource,
) resource.Resource {
	return resource.RegisterOutput(la, la.BaseAction, name, out, copyFrom...)
}

func (la *builderLogAction) Execute(ctx context.Context) error {
	builder := la.output

	// Default options
	if la.opts == nil {
		la.opts = &sdklog.Options{
			LintLevels: sdklog.LintLevelsDefault,
		}
	}

	format := la.opts.Format
	if format == nil {
		format = sdklog.FormatTable
	}

	// Log lint results if available
	if builder.lintResult != nil {
		if err := la.logLintResults(ctx, builder, format); err != nil {
			return err
		}
	}

	return nil
}

func (la *builderLogAction) logLintResults(ctx context.Context, builder *Builder, format *sdklog.Format) error {
	lintLevels := la.opts.LintLevels
	if lintLevels == nil {
		lintLevels = sdklog.LintLevelsDefault
	}

	for _, level := range lintLevels {
		if len(level.Severities) == 0 {
			continue
		}

		matching := la.getViolationsBySeverities(builder.lintResult, level.Severities)
		if len(matching) == 0 {
			continue
		}

		// Format matching violations
		formatted, err := la.formatLintOutput(matching, format, builder.options.Dockerfile)
		if err != nil {
			return err
		}

		// Log at appropriate level
		action := level.Action
		if action == nil {
			action = sdklog.ActionInfo
		}

		la.logAtLevel(ctx, builder.log, action, formatted)
	}

	return nil
}

func (*builderLogAction) logAtLevel(ctx context.Context, logger *slog.Logger, action *sdklog.Action, message string) {
	switch action {
	case sdklog.ActionError:
		logger.ErrorContext(ctx, message)
	case sdklog.ActionWarn:
		logger.WarnContext(ctx, message)
	case sdklog.ActionDebug:
		logger.DebugContext(ctx, message)
	default: // ActionInfo or unknown
		logger.InfoContext(ctx, message)
	}
}

func (*builderLogAction) getViolationsBySeverities(
	result *godolint2.Result,
	severities []*lint.Severity,
) []godolint2.Violation {
	severitySet := make(map[string]struct{}, len(severities))
	for _, sev := range severities {
		severitySet[sev.String()] = struct{}{}
	}

	var matching []godolint2.Violation

	for _, violation := range result.Violations {
		if _, ok := severitySet[string(violation.Severity)]; ok {
			matching = append(matching, violation)
		}
	}

	return matching
}

func (*builderLogAction) formatLintOutput(
	violations []godolint2.Violation,
	format *sdklog.Format,
	dockerfilePath string,
) (string, error) {
	switch format {
	case sdklog.FormatTable:
		return formatLintTable(violations), nil
	case sdklog.FormatJSON:
		bytes, err := json.MarshalIndent(violations, "", jsonIndent)
		if err != nil {
			return "", fmt.Errorf("%w: %w", sdklog.ErrFormatOutput, err)
		}

		return string(bytes), nil
	case sdklog.FormatSARIF:
		report := godolint2.FormatSARIF(violations, dockerfilePath)

		//nolint:musttag // https://github.com/omissis/go-jsonschema/issues/498
		bytes, err := json.MarshalIndent(report, "", jsonIndent)
		if err != nil {
			return "", fmt.Errorf("%w: %w", sdklog.ErrFormatOutput, err)
		}

		return string(bytes), nil
	default:
		return "", fmt.Errorf("%w: %s", sdklog.ErrFormatOutput, format.String())
	}
}

// formatLintTable formats lint results as a table.
func formatLintTable(violations []godolint2.Violation) string {
	cfg := devformat.TableConfig{
		Title:    "DOCKERFILE LINT RESULTS",
		EmptyMsg: "No Dockerfile issues found",
	}

	return devformat.Table(cfg, violations, func(v godolint2.Violation) ([]string, []string) {
		columns := []string{
			fmt.Sprintf("[%s] Line %d: %s", v.Severity, v.Line, v.Code),
		}

		return columns, []string{v.Message}
	})
}
