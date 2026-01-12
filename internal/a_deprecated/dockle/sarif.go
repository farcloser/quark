package dockle

import (
	"strings"

	"github.com/farcloser/quark/dev/format"
	"github.com/farcloser/quark/dev/format/sarif"
)

// FormatSARIF converts Dockle audit results to SARIF format.
// The imageRef is stored in run properties for reference.
func FormatSARIF(result *ScanResult, imageRef string) *sarif.SarifSchema210Json {
	report := format.NewSARIFReport()

	// Track unique rules for the rules array
	rulesMap := make(map[string]sarif.ReportingDescriptor)

	for _, detail := range result.Details {
		// Add rule if not already present
		if _, exists := rulesMap[detail.Code]; !exists {
			rulesMap[detail.Code] = format.NewSARIFRule(detail.Code, detail.Title)
		}

		// Create result with all alerts as message
		message := detail.Title
		if len(detail.Alerts) > 0 {
			message += ": " + strings.Join(detail.Alerts, ", ")
		}

		sarifResult := format.NewSARIFResult(
			detail.Code,
			mapAuditLevelToSARIF(detail.Level),
			message,
		)
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

// mapAuditLevelToSARIF maps Dockle level strings to SARIF result levels.
func mapAuditLevelToSARIF(level string) sarif.ResultLevel {
	switch level {
	case "FATAL":
		return format.SARIFLevelError
	case "WARN":
		return format.SARIFLevelWarning
	default:
		return format.SARIFLevelNote
	}
}
