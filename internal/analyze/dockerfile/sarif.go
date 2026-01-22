package dockerfile

import (
	"github.com/farcloser/quark/pkg/dev/format"
	"github.com/farcloser/quark/pkg/dev/format/sarif"
)

// FormatSARIF converts godolint violations to SARIF format.
// The dockerfilePath is used for physical location URIs.
func FormatSARIF(violations []Violation, dockerfilePath string) *sarif.SarifSchema210Json {
	report := format.NewSARIFReport()

	// Track unique rules for the rules array
	rulesMap := make(map[string]sarif.ReportingDescriptor)

	for _, violation := range violations {
		// Add rule if not already present
		if _, exists := rulesMap[violation.Code]; !exists {
			rulesMap[violation.Code] = format.NewSARIFRule(violation.Code, violation.Message)
		}

		// Create result with physical location
		sarifResult := format.NewSARIFResultWithLocation(
			violation.Code,
			mapLintSeverityToSARIF(violation.Severity),
			violation.Message,
			dockerfilePath,
			violation.Line,
		)
		report.Runs[0].Results = append(report.Runs[0].Results, sarifResult)
	}

	// Convert rules map to slice
	rules := make([]sarif.ReportingDescriptor, 0, len(rulesMap))
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	report.Runs[0].Tool.Driver.Rules = rules

	return report
}

// mapLintSeverityToSARIF maps godolint severity to SARIF result levels.
func mapLintSeverityToSARIF(severity Severity) sarif.ResultLevel {
	switch severity {
	case SeverityError:
		return format.SARIFLevelError
	case SeverityWarning:
		return format.SARIFLevelWarning
	default:
		return format.SARIFLevelNote
	}
}
