package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/trivy"
)

// ScanSeverity represents vulnerability severity.
//
//nolint:recvcheck // MarshalJSON uses value receiver, UnmarshalJSON requires pointer receiver
type ScanSeverity struct {
	value string
}

//nolint:gochecknoglobals // ScanSeverity enum pattern requires global variables
var (
	// SeverityUnknown represents unknown severity.
	SeverityUnknown = ScanSeverity{"UNKNOWN"}
	// SeverityLow represents low severity.
	SeverityLow = ScanSeverity{"LOW"}
	// SeverityMedium represents medium severity.
	SeverityMedium = ScanSeverity{"MEDIUM"}
	// SeverityHigh represents high severity.
	SeverityHigh = ScanSeverity{"HIGH"}
	// SeverityCritical represents critical severity.
	SeverityCritical = ScanSeverity{"CRITICAL"}
)

// String returns the string representation of the severity.
func (s ScanSeverity) String() string {
	return s.value
}

// MarshalJSON implements json.Marshaler for ScanSeverity.
func (s ScanSeverity) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // Standard library JSON marshaling
	return json.Marshal(s.value)
}

// UnmarshalJSON implements json.Unmarshaler for ScanSeverity.
func (s *ScanSeverity) UnmarshalJSON(data []byte) error {
	var str string
	//nolint:wrapcheck // Standard library JSON unmarshaling
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	// Normalize to uppercase
	normalized := strings.ToUpper(str)

	switch normalized {
	case "UNKNOWN":
		s.value = "UNKNOWN"
	case "LOW":
		s.value = "LOW"
	case "MEDIUM":
		s.value = "MEDIUM"
	case "HIGH":
		s.value = "HIGH"
	case "CRITICAL":
		s.value = "CRITICAL"
	default:
		return fmt.Errorf("%w: %q (valid: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)", ErrInvalidScanSeverity, str)
	}

	return nil
}

// ScanAction represents how to handle vulnerabilities at a severity threshold.
//
//nolint:recvcheck // MarshalJSON uses value receiver, UnmarshalJSON requires pointer receiver
type ScanAction struct {
	value string
}

//nolint:gochecknoglobals // ScanAction enum pattern requires global variables
var (
	// ActionError causes scan to fail (default).
	ActionError = ScanAction{"error"}
	// ActionWarn logs vulnerabilities as warnings without failing.
	ActionWarn = ScanAction{"warn"}
	// ActionInfo logs vulnerabilities as info without failing.
	ActionInfo = ScanAction{"info"}
)

// String returns the string representation of the action.
func (a ScanAction) String() string {
	return a.value
}

// MarshalJSON implements json.Marshaler for ScanAction.
func (a ScanAction) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // Standard library JSON marshaling
	return json.Marshal(a.value)
}

// UnmarshalJSON implements json.Unmarshaler for ScanAction.
func (a *ScanAction) UnmarshalJSON(data []byte) error {
	var str string
	//nolint:wrapcheck // Standard library JSON unmarshaling
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	// Normalize to lowercase
	normalized := strings.ToLower(str)

	switch normalized {
	case "error":
		a.value = "error"
	case "warn":
		a.value = "warn"
	case "info":
		a.value = "info"
	default:
		return fmt.Errorf("%w: %q (valid: error, warn, info)", ErrInvalidScanAction, str)
	}

	return nil
}

// ScanFormat represents scan output format.
//
//nolint:recvcheck // MarshalJSON uses value receiver, UnmarshalJSON requires pointer receiver
type ScanFormat struct {
	value string
}

//nolint:gochecknoglobals // ScanFormat enum pattern requires global variables
var (
	// FormatTable represents table output.
	FormatTable = ScanFormat{"table"}
	// FormatJSON represents JSON output.
	FormatJSON = ScanFormat{"json"}
	// FormatSARIF represents SARIF output.
	FormatSARIF = ScanFormat{"sarif"}
)

// String returns the string representation of the format.
func (f ScanFormat) String() string {
	return f.value
}

// MarshalJSON implements json.Marshaler for ScanFormat.
func (f ScanFormat) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // Standard library JSON marshaling
	return json.Marshal(f.value)
}

// UnmarshalJSON implements json.Unmarshaler for ScanFormat.
func (f *ScanFormat) UnmarshalJSON(data []byte) error {
	var str string
	//nolint:wrapcheck // Standard library JSON unmarshaling
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	// Normalize to lowercase
	normalized := strings.ToLower(str)

	switch normalized {
	case "table":
		f.value = "table"
	case "json":
		f.value = "json"
	case "sarif":
		f.value = "sarif"
	default:
		return fmt.Errorf("%w: %q (valid: table, json, sarif)", ErrInvalidScanFormat, str)
	}

	return nil
}

const (
	msgVulnerabilitiesFound = "vulnerabilities found at or above threshold"
)

// ScanSeverityCheck represents a threshold check with an action.
type ScanSeverityCheck struct {
	threshold ScanSeverity
	action    ScanAction
}

// Scan represents a vulnerability scan operation.
type Scan struct {
	opName         string
	image          *Image
	registry       *Registry
	severityChecks []ScanSeverityCheck
	format         ScanFormat
	timeout        time.Duration
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
	builder.scan.registry = builder.plan.getRegistry(image.Domain())

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

// Timeout sets the operation timeout.
// If not set, the operation will use the context timeout from Plan.Execute().
func (builder *ScanBuilder) Timeout(duration time.Duration) *ScanBuilder {
	builder.scan.timeout = duration

	return builder
}

// Build validates and adds the scan to the plan.
func (builder *ScanBuilder) Build() (*Scan, error) {
	if builder.scan.image == nil {
		return nil, ErrScanImageRequired
	}
	// Digest validation moved to execute() - digest may be populated during plan execution
	if len(builder.scan.severityChecks) == 0 {
		// Default to HIGH and CRITICAL with Error action
		builder.scan.severityChecks = []ScanSeverityCheck{
			{threshold: SeverityHigh, action: ActionError},
			{threshold: SeverityCritical, action: ActionError},
		}
	}

	if builder.scan.format == (ScanFormat{}) {
		builder.scan.format = FormatTable
	}

	builder.plan.scans = append(builder.plan.scans, builder.scan)
	builder.plan.operations = append(builder.plan.operations, builder.scan)

	return builder.scan, nil
}

func (scan *Scan) execute(ctx context.Context) error {
	// Apply timeout if configured
	if scan.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, scan.timeout)
		defer cancel()
	}

	// Validate digest is present (may have been populated during plan execution)
	if scan.image.Digest() == "" {
		return fmt.Errorf("%w: %s", ErrScanMustHaveDigest, scan.image.Name())
	}

	// Construct image reference for scanning
	// Prefer digest for immutability, fall back to tag
	var imageRef string

	var err error

	switch {
	case scan.image.Digest() != "":
		imageRef, err = scan.image.digestRef()
		if err != nil {
			return fmt.Errorf("failed to build digest reference: %w", err)
		}
	case scan.image.Version() != "":
		imageRef, err = scan.image.tagRef()
		if err != nil {
			return fmt.Errorf("failed to build tag reference: %w", err)
		}
	default:
		imageRef = scan.image.Name()
	}

	scan.log.Info().
		Str("image", imageRef).
		Str("format", scan.format.String()).
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

	result, err := scanner.ScanImage(
		ctx,
		imageRef,
		allSeverities,
		scan.format.String(),
		registryHost,
		username,
		password,
	)
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

		output, err := scanner.FormatOutput(thresholdResult, scan.format.String())
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		// Handle according to action
		switch check.action {
		case ActionError:
			scan.log.Error().
				Str("threshold", check.threshold.String()).
				Int("count", len(matchingVulns)).
				Msg(msgVulnerabilitiesFound)
			scan.log.Error().Msg(output)

			return fmt.Errorf("%w: %s", ErrVulnerabilitiesFound, check.threshold)

		case ActionWarn:
			scan.log.Warn().
				Str("threshold", check.threshold.String()).
				Int("count", len(matchingVulns)).
				Msg(msgVulnerabilitiesFound)
			scan.log.Warn().Msg(output)

		case ActionInfo:
			scan.log.Info().
				Str("threshold", check.threshold.String()).
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
	// Build severity order map using existing constants to avoid string duplication
	severityOrder := map[string]int{
		SeverityUnknown.value:  0,
		SeverityLow.value:      1,
		SeverityMedium.value:   2,
		SeverityHigh.value:     3,
		SeverityCritical.value: 4,
	}

	thresholdLevel := severityOrder[threshold.String()]

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

// operationName returns the scan operation name (implements operation interface).
func (scan *Scan) operationName() string {
	return scan.opName
}
