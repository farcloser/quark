package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	devformat "github.com/farcloser/quark/dev/format"
	"github.com/farcloser/quark/dev/format/sarif"
	"github.com/farcloser/quark/dev/resource"
	dockle2 "github.com/farcloser/quark/internal/a_deprecated/dockle"
	"github.com/farcloser/quark/sdk/audit"
	sdklog "github.com/farcloser/quark/sdk/logger"
	"github.com/farcloser/quark/sdk/platform"
	"github.com/farcloser/quark/sdk/scan"
)

const jsonIndent = "  "

type logAction struct {
	*resource.BaseAction

	opts   *sdklog.Options
	output *Image
}

func (la *logAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(la, la.BaseAction, name, out, copyFrom...)
}

func (la *logAction) Execute(ctx context.Context) error {
	img := la.output

	// Default options
	if la.opts == nil {
		la.opts = &sdklog.Options{
			AuditLevels: sdklog.AuditLevelsDefault,
			ScanLevels:  sdklog.ScanLevelsQuiet,
		}
	}

	format := la.opts.Format
	if format == nil {
		format = sdklog.FormatTable
	}

	// Log scan results if available
	if img.scanResult != nil {
		if err := la.logScanResults(ctx, img, format); err != nil {
			return err
		}
	}

	// Log audit results if available
	if img.auditResult != nil {
		if err := la.logAuditResults(ctx, img, format); err != nil {
			return err
		}
	}

	return nil
}

func (la *logAction) logScanResults(ctx context.Context, img *Image, format *sdklog.Format) error {
	scanLevels := la.opts.ScanLevels
	if scanLevels == nil {
		scanLevels = sdklog.ScanLevelsDefault
	}

	for _, level := range scanLevels {
		if len(level.Severities) == 0 {
			continue
		}

		matching := filterVulnerabilitiesBySeverity(img.scanResult, level.Severities)
		if len(matching) == 0 {
			continue
		}

		formatted, err := formatScanOutput(matching, format, img.ref.String())
		if err != nil {
			return err
		}

		// Log at appropriate level
		action := level.Action
		if action == nil {
			action = sdklog.ActionInfo
		}

		la.logAtLevel(ctx, img.log, action, formatted)
	}

	return nil
}

func (la *logAction) logAuditResults(ctx context.Context, img *Image, format *sdklog.Format) error {
	auditLevels := la.opts.AuditLevels
	if auditLevels == nil {
		auditLevels = sdklog.AuditLevelsDefault
	}

	for _, level := range auditLevels {
		if len(level.Severities) == 0 {
			continue
		}

		matching := la.getDetailsByLevels(img.auditResult, level.Severities)
		if len(matching) == 0 {
			continue
		}

		// Format matching issues
		matchingResult := &dockle2.ScanResult{
			Details: matching,
		}

		formatted, err := la.formatAuditOutput(matchingResult, format, img.ref.String())
		if err != nil {
			return err
		}

		// Log at appropriate level
		action := level.Action
		if action == nil {
			action = sdklog.ActionInfo
		}

		la.logAtLevel(ctx, img.log, action, formatted)
	}

	return nil
}

func (*logAction) logAtLevel(ctx context.Context, logger *slog.Logger, action *sdklog.Action, message string) {
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

// filterVulnerabilitiesBySeverity returns vulnerabilities matching the given severities.
func filterVulnerabilitiesBySeverity(result *scan.Result, severities []*scan.Severity) []scan.Vulnerability {
	severitySet := make(map[*scan.Severity]struct{}, len(severities))
	for _, sev := range severities {
		severitySet[sev] = struct{}{}
	}

	var matching []scan.Vulnerability

	for _, vuln := range result.Vulnerabilities {
		if _, ok := severitySet[vuln.Severity]; ok {
			matching = append(matching, vuln)
		}
	}

	return matching
}

func (*logAction) getDetailsByLevels(
	result *dockle2.ScanResult,
	severities []*audit.Severity,
) []dockle2.Detail {
	levelSet := make(map[string]struct{}, len(severities))
	for _, sev := range severities {
		levelSet[sev.String()] = struct{}{}
	}

	var matching []dockle2.Detail

	for _, detail := range result.Details {
		if _, ok := levelSet[detail.Level]; ok {
			matching = append(matching, detail)
		}
	}

	return matching
}

func formatScanOutput(
	vulns []scan.Vulnerability,
	format *sdklog.Format,
	imageRef string,
) (string, error) {
	switch format {
	case sdklog.FormatTable:
		return formatScanTable(vulns), nil
	case sdklog.FormatJSON:
		bytes, err := json.MarshalIndent(vulns, "", jsonIndent)
		if err != nil {
			return "", fmt.Errorf("%w: %w", sdklog.ErrFormatOutput, err)
		}

		return string(bytes), nil
	case sdklog.FormatSARIF:
		report := formatScanSARIF(vulns, imageRef)

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

func (*logAction) formatAuditOutput(result *dockle2.ScanResult, format *sdklog.Format, imageRef string) (string, error) {
	switch format {
	case sdklog.FormatTable:
		return formatAuditTable(result), nil
	case sdklog.FormatJSON:
		bytes, err := json.MarshalIndent(result, "", jsonIndent)
		if err != nil {
			return "", fmt.Errorf("%w: %w", sdklog.ErrFormatOutput, err)
		}

		return string(bytes), nil
	case sdklog.FormatSARIF:
		report := dockle2.FormatSARIF(result, imageRef)

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

// formatScanTable formats scan results as a table.
func formatScanTable(vulns []scan.Vulnerability) string {
	cfg := devformat.TableConfig{
		Title:    "VULNERABILITY SCAN RESULTS",
		EmptyMsg: "No vulnerabilities found",
	}

	return devformat.Table(cfg, vulns, func(vuln scan.Vulnerability) ([]string, []string) {
		columns := []string{
			fmt.Sprintf("[%s] %s", vuln.Severity.String(), vuln.ID),
			fmt.Sprintf("%s (%s)", vuln.PkgName, vuln.InstalledVersion),
		}

		var details []string
		if vuln.PURL != "" {
			details = append(details, "PURL: "+vuln.PURL)
		}

		if len(vuln.Targets) > 0 {
			details = append(details, "Targets: "+formatTargets(vuln.Targets))
		}

		if vuln.FixedVersion != "" {
			details = append(details, "Fixed in: "+vuln.FixedVersion)
		}

		if vuln.Title != "" {
			details = append(details, vuln.Title)
		}

		return columns, details
	})
}

// formatTargets formats the Targets map as a human-readable string.
// e.g., "Node.js (linux/amd64, linux/arm64), alpine:3.19 (linux/amd64)".
func formatTargets(targets map[string][]*platform.Platform) string {
	// Sort target names for consistent output
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}

	sort.Strings(names)

	var parts []string

	for _, name := range names {
		platforms := targets[name]
		if len(platforms) == 0 {
			parts = append(parts, name)

			continue
		}

		platStrs := make([]string, len(platforms))
		for idx, p := range platforms {
			platStrs[idx] = p.String()
		}

		parts = append(parts, fmt.Sprintf("%s (%s)", name, strings.Join(platStrs, ", ")))
	}

	return strings.Join(parts, ", ")
}

// formatAuditTable formats audit results as a table.
func formatAuditTable(result *dockle2.ScanResult) string {
	cfg := devformat.TableConfig{
		Title:    "IMAGE AUDIT RESULTS",
		EmptyMsg: "No image issues found",
	}

	return devformat.Table(cfg, result.Details, func(detail dockle2.Detail) ([]string, []string) {
		columns := []string{
			fmt.Sprintf("[%s] %s", detail.Level, detail.Code),
			detail.Title,
		}

		details := make([]string, len(detail.Alerts))
		for idx, alert := range detail.Alerts {
			details[idx] = "- " + alert
		}

		return columns, details
	})
}

// formatScanSARIF converts scan results to SARIF format.
func formatScanSARIF(vulns []scan.Vulnerability, imageRef string) *sarif.SarifSchema210Json {
	report := devformat.NewSARIFReport()

	// Track unique rules (CVE IDs) for the rules array
	rulesMap := make(map[string]sarif.ReportingDescriptor)

	for _, vuln := range vulns {
		// Add rule if not already present
		if _, exists := rulesMap[vuln.ID]; !exists {
			description := vuln.Title
			if description == "" {
				description = vuln.ID
			}

			rulesMap[vuln.ID] = devformat.NewSARIFRule(vuln.ID, description)
		}

		// Create result
		message := formatVulnMessage(vuln)
		level := mapSeverityToSARIFLevel(vuln.Severity)
		sarifResult := devformat.NewSARIFResult(vuln.ID, level, message)
		report.Runs[0].Results = append(report.Runs[0].Results, sarifResult)
	}

	// Convert rules map to slice
	rules := make([]sarif.ReportingDescriptor, 0, len(rulesMap))
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	report.Runs[0].Tool.Driver.Rules = rules

	// Store image reference in run properties
	if imageRef != "" {
		report.Runs[0].Properties = &sarif.PropertyBag{
			AdditionalProperties: map[string]any{
				"imageName": imageRef,
			},
		}
	}

	return report
}

func formatVulnMessage(vuln scan.Vulnerability) string {
	msg := vuln.PkgName + " " + vuln.InstalledVersion

	if vuln.FixedVersion != "" {
		msg += " (fix available: " + vuln.FixedVersion + ")"
	}

	if len(vuln.Targets) > 0 {
		msg += " in " + formatTargets(vuln.Targets)
	}

	if vuln.PURL != "" {
		msg += " [" + vuln.PURL + "]"
	}

	return msg
}

func mapSeverityToSARIFLevel(sev *scan.Severity) sarif.ResultLevel {
	switch sev {
	case scan.SeverityCritical, scan.SeverityHigh:
		return devformat.SARIFLevelError
	case scan.SeverityMedium:
		return devformat.SARIFLevelWarning
	default:
		return devformat.SARIFLevelNote
	}
}
