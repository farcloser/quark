package trivy

import (
	"github.com/farcloser/quark/pkg/dev/format"
	"github.com/farcloser/quark/pkg/dev/format/sarif"
)

// FormatSARIF converts Trivy scan results to SARIF format.
// The imageRef is stored in run properties for reference.
func FormatSARIF(vulns []Vulnerability, imageRef string) *sarif.SarifSchema210Json {
	report := format.NewSARIFReport()

	// Track unique rules (CVE IDs) for the rules array
	rulesMap := make(map[string]sarif.ReportingDescriptor)

	for _, vuln := range vulns {
		// Add rule if not already present
		if _, exists := rulesMap[vuln.VulnerabilityID]; !exists {
			description := vuln.Title
			if description == "" {
				description = vuln.VulnerabilityID
			}

			rulesMap[vuln.VulnerabilityID] = format.NewSARIFRule(vuln.VulnerabilityID, description)
		}

		// Create result
		message := formatVulnMessage(vuln)
		sarifResult := format.NewSARIFResult(
			vuln.VulnerabilityID,
			mapVulnSeverityToLevel(vuln.Severity),
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

// formatVulnMessage creates a human-readable message for a vulnerability.
func formatVulnMessage(vuln Vulnerability) string {
	msg := vuln.PkgName + " " + vuln.InstalledVersion

	if vuln.FixedVersion != "" {
		msg += " (fix available: " + vuln.FixedVersion + ")"
	}

	if vuln.PkgIdentifier.PURL != "" {
		msg += " [" + vuln.PkgIdentifier.PURL + "]"
	}

	return msg
}

// mapVulnSeverityToLevel maps Trivy severity strings to SARIF result levels.
func mapVulnSeverityToLevel(severity string) sarif.ResultLevel {
	switch severity {
	case Critical, High:
		return format.SARIFLevelError
	case Medium:
		return format.SARIFLevelWarning
	default:
		return format.SARIFLevelNote
	}
}
