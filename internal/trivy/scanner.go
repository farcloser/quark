// Package trivy provides Trivy vulnerability scanner wrapper.
package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/tools"
)

var errUnsupportedFormat = errors.New("unsupported format")

// Scanner wraps Trivy CLI operations.
type Scanner struct {
	log       zerolog.Logger
	installer *tools.Installer
}

// NewScanner creates a new Trivy scanner.
func NewScanner(log zerolog.Logger) *Scanner {
	return &Scanner{
		log:       log,
		installer: tools.NewInstaller(log),
	}
}

// Severity represents vulnerability severity levels.
type Severity string

const (
	// SeverityUnknown represents unknown severity.
	SeverityUnknown Severity = "UNKNOWN"
	// SeverityLow represents low severity.
	SeverityLow Severity = "LOW"
	// SeverityMedium represents medium severity.
	SeverityMedium Severity = "MEDIUM"
	// SeverityHigh represents high severity.
	SeverityHigh Severity = "HIGH"
	// SeverityCritical represents critical severity.
	SeverityCritical Severity = "CRITICAL"
)

// Vulnerability represents a single vulnerability finding.
//
//nolint:tagliatelle
type Vulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
}

// Result represents a scan result for a specific target.
//
//nolint:tagliatelle
type Result struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

// ScanResult represents Trivy scan results.
//
//nolint:tagliatelle
type ScanResult struct {
	Results []Result `json:"Results"`
}

// ScanImage scans an image for vulnerabilities across multiple platforms.
// Always scans both linux/amd64 and linux/arm64 platforms and aggregates results.
// If registry credentials are provided, logs in to the registry before scanning.
func (scanner *Scanner) ScanImage(
	ctx context.Context,
	imageRef string,
	severities []Severity,
	outputFormat string,
	registryHost string,
	username string,
	password string,
) (*ScanResult, error) {
	// Ensure trivy is installed
	trivyPath, err := scanner.installer.Ensure(tools.Trivy)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure trivy is installed: %w", err)
	}

	// Login to registry if credentials provided
	if registryHost != "" && username != "" && password != "" {
		if err := scanner.registryLogin(ctx, trivyPath, registryHost, username, password); err != nil {
			return nil, fmt.Errorf("failed to login to registry: %w", err)
		}
	}

	scanner.log.Info().
		Str("image", imageRef).
		Strs("platforms", []string{"linux/amd64", "linux/arm64"}).
		Msg("scanning image across multiple platforms")

	// Scan both required platforms
	platforms := []string{"linux/amd64", "linux/arm64"}

	var aggregatedResult ScanResult

	for _, platform := range platforms {
		scanner.log.Debug().
			Str("platform", platform).
			Msg("scanning platform")

		result, err := scanner.scanPlatform(ctx, trivyPath, imageRef, platform, severities, outputFormat)
		if err != nil {
			return nil, fmt.Errorf("failed to scan platform %s: %w", platform, err)
		}

		// Aggregate results from all platforms
		aggregatedResult.Results = append(aggregatedResult.Results, result.Results...)
	}

	scanner.log.Info().
		Int("total_results", len(aggregatedResult.Results)).
		Msg("multi-platform scan complete")

	return &aggregatedResult, nil
}

// scanPlatform scans a specific platform.
func (scanner *Scanner) scanPlatform(
	ctx context.Context,
	trivyPath string,
	imageRef string,
	platform string,
	severities []Severity,
	_ string,
) (*ScanResult, error) {
	// Build Trivy command with platform
	args := []string{
		"image",
		"--platform", platform,
		"--format", "json", // Always use JSON for parsing
		"--severity", strings.Join(severityStrings(severities), ","),
		"--quiet", // Suppress progress output
		imageRef,
	}

	//nolint:gosec // Command args are from trusted config
	cmd := exec.CommandContext(ctx, trivyPath, args...)

	// Separate stdout and stderr to avoid mixing JSON with progress messages
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr != nil {
		// Trivy returns non-zero exit code when vulnerabilities are found
		// We still want to parse the output in this case
		scanner.log.Debug().
			Err(runErr).
			Str("platform", platform).
			Str("stderr", stderr.String()).
			Msg("trivy command completed with exit code")
	}

	// Log stderr if present (progress messages, warnings)
	if stderr.Len() > 0 {
		scanner.log.Debug().
			Str("platform", platform).
			Str("stderr", stderr.String()).
			Msg("trivy stderr output")
	}

	// Parse JSON output from stdout
	var result ScanResult
	if err := json.Unmarshal([]byte(stdout.String()), &result); err != nil {
		scanner.log.Error().
			Str("platform", platform).
			Str("stdout", stdout.String()).
			Str("stderr", stderr.String()).
			Msg("failed to parse trivy JSON output")

		return nil, fmt.Errorf("failed to parse Trivy output: %w", err)
	}

	scanner.log.Debug().
		Str("platform", platform).
		Int("vulnerabilities", countVulnerabilities(&result)).
		Msg("platform scan complete")

	return &result, nil
}

// FormatOutput formats scan results for display.
func (*Scanner) FormatOutput(result *ScanResult, format string) (string, error) {
	switch format {
	case "table":
		return formatTable(result), nil
	case "json":
		bytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON: %w", err)
		}

		return string(bytes), nil
	default:
		return "", fmt.Errorf("%w: %s", errUnsupportedFormat, format)
	}
}

// CheckThreshold checks if scan results exceed severity threshold.
func (*Scanner) CheckThreshold(result *ScanResult, severities []Severity) bool {
	for _, scanResult := range result.Results {
		for _, vuln := range scanResult.Vulnerabilities {
			for _, sev := range severities {
				if vuln.Severity == string(sev) {
					return true // Threshold exceeded
				}
			}
		}
	}

	return false
}

func severityStrings(severities []Severity) []string {
	strs := make([]string, len(severities))
	for idx, sev := range severities {
		strs[idx] = string(sev)
	}

	return strs
}

func countVulnerabilities(result *ScanResult) int {
	count := 0
	for _, scanResult := range result.Results {
		count += len(scanResult.Vulnerabilities)
	}

	return count
}

func formatTable(result *ScanResult) string {
	var builder strings.Builder

	_, _ = builder.WriteString("VULNERABILITY SCAN RESULTS\n")
	_, _ = builder.WriteString(strings.Repeat("=", 80) + "\n\n")

	totalVulns := 0

	for _, scanResult := range result.Results {
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

// registryLogin logs in to a registry using trivy registry login.
// This stores credentials in Docker's config (~/.docker/config.json) and keeps
// them out of the process list. Credentials are only sent to the specific registry.
func (scanner *Scanner) registryLogin(ctx context.Context, trivyPath, registryHost, username, password string) error {
	scanner.log.Debug().
		Str("registry", registryHost).
		Msg("logging in to registry")

	// Use --password-stdin to avoid password in process list
	cmd := exec.CommandContext(
		ctx,
		trivyPath,
		"registry",
		"login",
		registryHost,
		"--username",
		username,
		"--password-stdin",
	)
	cmd.Stdin = strings.NewReader(password)

	// Capture output for error reporting
	output, err := cmd.CombinedOutput()
	if err != nil {
		scanner.log.Error().
			Str("output", string(output)).
			Msg("registry login failed")

		return fmt.Errorf("trivy registry login failed: %w\n%s", err, output)
	}

	scanner.log.Debug().
		Str("registry", registryHost).
		Msg("registry login successful")

	return nil
}
