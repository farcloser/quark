package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/trivy"
	"github.com/farcloser/quark/sdk/platform"
	"github.com/farcloser/quark/sdk/scan"
)

const (
	msgVulnerabilitiesFound = "vulnerabilities found matching severity filter"
)

type scanAction struct {
	resource.BaseResource[scanAction]

	log    *slog.Logger
	opts   *scan.Options
	image  *Image
	result *trivy.ScanResult
}

func (sa *scanAction) Execute(ctx context.Context) error {
	// Scan can only scan by digest. Fail first if digest is NOT set
	if sa.image.ref.Digest == "" {
		return fmt.Errorf("%w: %s", scan.ErrArgumentRequiredImageDigest, sa.image.ref.String())
	}

	if sa.opts == nil {
		sa.opts = &scan.Options{}
	}

	if sa.opts.Format == nil {
		sa.opts.Format = scan.FormatTable
	}

	if sa.opts.SeverityChecks == nil {
		sa.opts.SeverityChecks = scan.SetSeverityCheckRecommended
	}

	// Create Trivy scanner
	scanner, err := trivy.NewScanner(ctx, sa.log)
	if err != nil {
		return fmt.Errorf("%w: %w", scan.ErrRequirementsFailed, err)
	}

	result, err := scanner.ScanImage(
		ctx,
		sa.image.ref.String(),
		sa.image.registry.credentials(),
		[]string{platform.AMD64.String(), platform.ARM64.String()},
	)
	if err != nil {
		return fmt.Errorf("%w: %w", scan.ErrScanFailed, err)
	}

	for _, check := range sa.opts.SeverityChecks {
		// Skip if no severities specified
		if len(check.Severities) == 0 {
			sa.log.Warn("no severities set for severity check, ignoring")

			continue
		}

		matchingVulns := sa.getVulnerabilitiesBySeverities(result, check.Severities, sa.opts.Ignore)
		if len(matchingVulns) == 0 {
			continue // No vulnerabilities matching these severities, skip
		}

		// Format output for matching vulnerabilities
		matchingResult := []*trivy.Result{
			{
				Target:          result.Results[0].Target,
				Vulnerabilities: matchingVulns,
			},
		}

		output, err := sa.FormatOutput(matchingResult, sa.opts.Format)
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		// Handle according to action (default to error if not specified)
		action := check.Action
		if action == nil {
			action = scan.ActionError
		}

		severitiesStr := severitiesToString(check.Severities)

		switch action { //revive:disable-line:enforce-switch-style
		case scan.ActionError:
			sa.log.Error(msgVulnerabilitiesFound,
				slog.String("severities", severitiesStr),
				slog.Int("count", len(matchingVulns)),
			)
			sa.log.Error(output)

			return fmt.Errorf("%w: %s", scan.ErrVulnerable, severitiesStr)

		case scan.ActionWarn:
			sa.log.Warn(msgVulnerabilitiesFound,
				slog.String("severities", severitiesStr),
				slog.Int("count", len(matchingVulns)),
			)
			sa.log.Warn(output)

		case scan.ActionInfo:
			sa.log.Info(msgVulnerabilitiesFound,
				slog.String("severities", severitiesStr),
				slog.Int("count", len(matchingVulns)),
			)
			sa.log.Info(output)
		case scan.ActionDebug:
			sa.log.Debug(msgVulnerabilitiesFound,
				slog.String("severities", severitiesStr),
				slog.Int("count", len(matchingVulns)),
			)
			sa.log.Debug(output)
		}
	}

	sa.result = result

	return nil
}

// severitiesToString converts a slice of severities to a comma-separated string.
func severitiesToString(severities []*scan.Severity) string {
	strs := make([]string, len(severities))
	for i, sev := range severities {
		strs[i] = sev.String()
	}

	return strings.Join(strs, ",")
}

// FormatOutput formats scan results for display.
func (*scanAction) FormatOutput(result []*trivy.Result, format *scan.Format) (string, error) {
	switch format {
	case scan.FormatTable:
		return formatScanTable(result), nil
	case scan.FormatJSON:
		bytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", err
		}

		return string(bytes), nil
	default:
		// case scan.FormatSARIF:
		panic("not implemented")
	}
}

// getVulnerabilitiesBySeverities returns vulnerabilities matching any of the specified severities,
// excluding any CVEs in the ignore list.
func (*scanAction) getVulnerabilitiesBySeverities(
	result *trivy.ScanResult,
	severities []*scan.Severity,
	ignore []string,
) []trivy.Vulnerability {
	// Build a set of severity strings for O(1) lookup
	severitySet := make(map[string]struct{}, len(severities))
	for _, sev := range severities {
		severitySet[sev.String()] = struct{}{}
	}

	// Build a set of ignored CVE IDs for O(1) lookup
	ignoreSet := make(map[string]struct{}, len(ignore))
	for _, cve := range ignore {
		ignoreSet[cve] = struct{}{}
	}

	var matching []trivy.Vulnerability

	for _, scanResult := range result.Results {
		for _, vuln := range scanResult.Vulnerabilities {
			// Skip if CVE is in ignore list
			if _, ignored := ignoreSet[vuln.VulnerabilityID]; ignored {
				continue
			}

			if _, ok := severitySet[vuln.Severity]; ok {
				matching = append(matching, vuln)
			}
		}
	}

	return matching
}

func formatScanTable(result []*trivy.Result) string {
	var builder strings.Builder

	_, _ = builder.WriteString("VULNERABILITY SCAN RESULTS\n")
	_, _ = builder.WriteString(strings.Repeat("=", 80) + "\n\n")

	totalVulns := 0

	for _, scanResult := range result {
		if len(scanResult.Vulnerabilities) == 0 {
			continue
		}

		_, _ = builder.WriteString(fmt.Sprintf("Target: %s\n", scanResult.Target))
		_, _ = builder.WriteString(strings.Repeat("-", 80) + "\n")

		for _, vuln := range scanResult.Vulnerabilities {
			totalVulns++

			_, _ = builder.WriteString(fmt.Sprintf(
				"[%s] %s - %s (%s)\n",
				vuln.Severity,
				vuln.VulnerabilityID,
				vuln.PkgName,
				vuln.InstalledVersion,
			))

			if vuln.FixedVersion != "" {
				_, _ = builder.WriteString(fmt.Sprintf("  Fixed in: %s\n", vuln.FixedVersion))
			}

			if vuln.Title != "" {
				_, _ = builder.WriteString(fmt.Sprintf("  %s\n", vuln.Title))
			}

			_, _ = builder.WriteString("\n")
		}
	}

	_, _ = builder.WriteString(strings.Repeat("=", 80) + "\n")
	_, _ = builder.WriteString(fmt.Sprintf("Total vulnerabilities: %d\n", totalVulns))

	return builder.String()
}
