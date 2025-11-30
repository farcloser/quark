package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/trivy"
)

// ScanSeverity represents vulnerability severity.
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

	// scanMutex serializes scan operations to avoid Trivy database lock contention.
	scanMutex sync.Mutex
)

// String returns the string representation of the severity.
func (s *ScanSeverity) String() string {
	return s.value
}

// MarshalJSON implements json.Marshaler for ScanSeverity.
func (s *ScanSeverity) MarshalJSON() ([]byte, error) {
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
func (a *ScanAction) String() string {
	return a.value
}

// MarshalJSON implements json.Marshaler for ScanAction.
func (a *ScanAction) MarshalJSON() ([]byte, error) {
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
func (f *ScanFormat) String() string {
	return f.value
}

// MarshalJSON implements json.Marshaler for ScanFormat.
func (f *ScanFormat) MarshalJSON() ([]byte, error) {
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
	Threshold ScanSeverity `json:"threshold"`
	Action    ScanAction   `json:"action"`
}

// ScanArgs contains configuration options for creating a scan operation.
type ScanArgs struct {
	Description    string              // Required - operation name
	Source         *Image              // Required - image to scan
	SeverityChecks []ScanSeverityCheck // Optional - severity checks (default: HIGH+CRITICAL error)
	Format         ScanFormat          // Optional - output format (default: table)
	Timeout        time.Duration       // Optional - operation timeout
}

// scanOp represents a vulnerability scan operation.
type scanOp struct {
	opName         string
	image          *Image
	registry       *Registry
	severityChecks []ScanSeverityCheck
	format         ScanFormat
	timeout        time.Duration
	log            zerolog.Logger
}

func (s *scanOp) execute(ctx context.Context) error {
	// Serialize scans to avoid Trivy database lock contention
	scanMutex.Lock()
	defer scanMutex.Unlock()

	// Apply timeout if configured
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	// Validate digest is present (may have been populated during plan execution)
	if s.image.Digest() == "" {
		return fmt.Errorf("%w: %s", ErrScanMustHaveDigest, s.image.Name())
	}

	// Construct image reference for scanning
	// Prefer digest for immutability, fall back to tag
	var imageRef string

	var err error

	switch {
	case s.image.Digest() != "":
		imageRef, err = s.image.digestRef()
		if err != nil {
			return fmt.Errorf("failed to build digest reference: %w", err)
		}
	case s.image.Version() != "":
		imageRef = s.image.tagRef()
	default:
		imageRef = s.image.Name()
	}

	s.log.Info().
		Str("image", imageRef).
		Str("format", s.format.String()).
		Msg("scanning image")

	// Create Trivy scanner
	scanner := trivy.NewScanner(s.log)

	// Extract registry credentials if provided
	var registryHost, username, password string
	if s.registry != nil {
		registryHost = s.registry.domain
		username = s.registry.username
		password = s.registry.token
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
		s.format.String(),
		registryHost,
		username,
		password,
	)
	if err != nil {
		return fmt.Errorf("failed to scan image: %w", err)
	}

	// Process severity checks sequentially (fail-fast on first Error)
	for _, check := range s.severityChecks {
		// Get vulnerabilities at or above this threshold
		matchingVulns := getVulnerabilitiesAtOrAbove(result, check.Threshold)

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

		output, err := scanner.FormatOutput(thresholdResult, s.format.String())
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		// Handle according to action
		switch check.Action {
		case ActionError:
			s.log.Error().
				Str("threshold", check.Threshold.String()).
				Int("count", len(matchingVulns)).
				Msg(msgVulnerabilitiesFound)
			s.log.Error().Msg(output)

			return fmt.Errorf("%w: %s", ErrVulnerabilitiesFound, check.Threshold)

		case ActionWarn:
			s.log.Warn().
				Str("threshold", check.Threshold.String()).
				Int("count", len(matchingVulns)).
				Msg(msgVulnerabilitiesFound)
			s.log.Warn().Msg(output)

		case ActionInfo:
			s.log.Info().
				Str("threshold", check.Threshold.String()).
				Int("count", len(matchingVulns)).
				Msg(msgVulnerabilitiesFound)
			s.log.Info().Msg(output)
		}
	}

	s.log.Info().Msg("scan complete")

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
func (s *scanOp) operationName() string {
	return s.opName
}
