package sdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/trivy"
)

const msgVulnerabilitiesFound = "vulnerabilities found at or above threshold"

var (
	errScanMustHaveDigest = errors.New(
		"scan image MUST have digest specified (scanning by tag alone is not allowed)",
	)
	errVulnerabilitiesFoundAtAboveThreshold = errors.New(msgVulnerabilitiesFound)
)

// ScanSeverity represents vulnerability severity.
type ScanSeverity string

const (
	// SeverityUnknown represents unknown severity.
	SeverityUnknown ScanSeverity = "UNKNOWN"
	// SeverityLow represents low severity.
	SeverityLow ScanSeverity = "LOW"
	// SeverityMedium represents medium severity.
	SeverityMedium ScanSeverity = "MEDIUM"
	// SeverityHigh represents high severity.
	SeverityHigh ScanSeverity = "HIGH"
	// SeverityCritical represents critical severity.
	SeverityCritical ScanSeverity = "CRITICAL"
)

// ScanAction represents how to handle vulnerabilities at a severity threshold.
type ScanAction string

const (
	// ActionError causes scan to fail (default).
	ActionError ScanAction = "error"
	// ActionWarn logs vulnerabilities as warnings without failing.
	ActionWarn ScanAction = "warn"
	// ActionInfo logs vulnerabilities as info without failing.
	ActionInfo ScanAction = "info"
)

// ScanFormat represents scan output format.
type ScanFormat string

const (
	// FormatTable represents table output.
	FormatTable ScanFormat = "table"
	// FormatJSON represents JSON output.
	FormatJSON ScanFormat = "json"
	// FormatSARIF represents SARIF output.
	FormatSARIF ScanFormat = "sarif"
)

// ScanSeverityCheck represents a threshold check with an action.
type ScanSeverityCheck struct {
	threshold ScanSeverity
	action    ScanAction
}

// Scan represents a vulnerability scan operation.
type Scan struct {
	name           string
	image          *Image
	registry       *Registry
	severityChecks []ScanSeverityCheck
	format         ScanFormat
	log            zerolog.Logger
}

// ScanBuilder builds a Scan.
type ScanBuilder struct {
	plan *Plan
	scan *Scan
}

// Source sets the image to scan.
// The image must have a digest specified for secure scanning.
// Registry credentials are looked up from the plan's registry collection using the image domain.
// If no registry is found, anonymous access will be used.
func (builder *ScanBuilder) Source(image *Image) *ScanBuilder {
	builder.scan.image = image
	builder.scan.registry = builder.plan.getRegistry(image.domain)

	return builder
}

// Severity adds a severity threshold check.
// If action is not provided, defaults to ActionError (fail on match).
// Multiple calls are processed sequentially - first Error stops execution.
//
// Examples:
//
//	.ScanSeverity(SeverityCritical)                  // Fail if CRITICAL found
//	.ScanSeverity(SeverityMedium, ActionWarn)        // Warn if MEDIUM+ found
//	.ScanSeverity(SeverityLow, ActionInfo)           // Info if LOW+ found
func (builder *ScanBuilder) Severity(threshold ScanSeverity, action ...ScanAction) *ScanBuilder {
	selectedAction := ActionError // default
	if len(action) > 0 {
		selectedAction = action[0]
	}

	builder.scan.severityChecks = append(builder.scan.severityChecks, ScanSeverityCheck{
		threshold: threshold,
		action:    selectedAction,
	})

	return builder
}

// Format sets the output format.
func (builder *ScanBuilder) Format(format ScanFormat) *ScanBuilder {
	builder.scan.format = format

	return builder
}

// Build validates and adds the scan to the plan.
func (builder *ScanBuilder) Build() *Scan {
	if builder.scan.image == nil {
		builder.scan.log.Fatal().Msg("scan image is required")
	}
	// Digest validation moved to execute() - digest may be populated during plan execution
	if len(builder.scan.severityChecks) == 0 {
		// Default to HIGH and CRITICAL with Error action
		builder.scan.severityChecks = []ScanSeverityCheck{
			{threshold: SeverityHigh, action: ActionError},
			{threshold: SeverityCritical, action: ActionError},
		}
	}

	if builder.scan.format == "" {
		builder.scan.format = FormatTable
	}

	builder.plan.scans = append(builder.plan.scans, builder.scan)

	return builder.scan
}

func (scan *Scan) execute(_ context.Context) error {
	// Validate digest is present (may have been populated during plan execution)
	if scan.image.digest == "" {
		return fmt.Errorf("%w: %s", errScanMustHaveDigest, scan.image.name)
	}

	// Construct image reference for scanning
	// Prefer digest for immutability, fall back to tag
	var imageRef string

	switch {
	case scan.image.digest != "":
		imageRef = scan.image.digestRef()
	case scan.image.version != "":
		imageRef = scan.image.tagRef()
	default:
		imageRef = scan.image.name
	}

	scan.log.Info().
		Str("image", imageRef).
		Str("format", string(scan.format)).
		Msg("scanning image")

	// Create Trivy scanner
	scanner := trivy.NewScanner(scan.log)

	// Extract registry credentials if provided
	var registryHost, username, password string
	if scan.registry != nil {
		registryHost = scan.registry.host
		username = scan.registry.username
		password = scan.registry.password
	}

	// Run Trivy scan ONCE with ALL severity levels to get complete results
	allSeverities := []trivy.Severity{
		trivy.SeverityUnknown,
		trivy.SeverityLow,
		trivy.SeverityMedium,
		trivy.SeverityHigh,
		trivy.SeverityCritical,
	}

	result, err := scanner.ScanImage(imageRef, allSeverities, string(scan.format), registryHost, username, password)
	if err != nil {
		return fmt.Errorf("failed to scan image: %w", err)
	}

	// Process severity checks sequentially (fail-fast on first Error)
	for _, check := range scan.severityChecks {
		// Get vulnerabilities at or above this threshold
		matchingVulns := getVulnerabilitiesAtOrAbove(result, check.threshold)

		if len(matchingVulns) == 0 {
			continue // No vulnerabilities at this threshold, skip
		}

		// ScanFormat output for this threshold
		thresholdResult := &trivy.ScanResult{
			Results: []trivy.Result{
				{
					Target:          result.Results[0].Target,
					Vulnerabilities: matchingVulns,
				},
			},
		}

		output, err := scanner.FormatOutput(thresholdResult, string(scan.format))
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		// Handle according to action
		switch check.action {
		case ActionError:
			scan.log.Error().
				Str("threshold", string(check.threshold)).
				Int("count", len(matchingVulns)).
				Msg(msgVulnerabilitiesFound)
			scan.log.Error().Msg(output)

			return fmt.Errorf("%w: %s", errVulnerabilitiesFoundAtAboveThreshold, check.threshold)

		case ActionWarn:
			scan.log.Warn().
				Str("threshold", string(check.threshold)).
				Int("count", len(matchingVulns)).
				Msg(msgVulnerabilitiesFound)
			scan.log.Warn().Msg(output)

		case ActionInfo:
			scan.log.Info().
				Str("threshold", string(check.threshold)).
				Int("count", len(matchingVulns)).
				Msg(msgVulnerabilitiesFound)
			scan.log.Info().Msg(output)
		}
	}

	scan.log.Info().Msg("scan complete")

	return nil
}

// getVulnerabilitiesAtOrAbove returns vulnerabilities at or above the given severity threshold.
func getVulnerabilitiesAtOrAbove(result *trivy.ScanResult, threshold ScanSeverity) []trivy.Vulnerability {
	severityOrder := map[string]int{
		"UNKNOWN":  0,
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	thresholdLevel := severityOrder[string(threshold)]

	var matching []trivy.Vulnerability

	for _, scanResult := range result.Results {
		for _, vuln := range scanResult.Vulnerabilities {
			vulnLevel := severityOrder[vuln.Severity]
			if vulnLevel >= thresholdLevel {
				matching = append(matching, vuln)
			}
		}
	}

	return matching
}
