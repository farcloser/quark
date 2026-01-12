package scan

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/internal/trivy"
	"github.com/farcloser/quark/sdk/platform"
)

// Options contains configuration for vulnerability scanning.
type Options struct {
	// ShowSuppressed logs vulnerabilities that were filtered by VEX attestations.
	ShowSuppressed bool
}

// Result holds deduplicated vulnerability scan results.
type Result struct {
	Vulnerabilities []Vulnerability
}

// Vulnerability represents a unique vulnerability (CVE + package).
// Each vulnerability appears once, with Targets tracking where it was found.
type Vulnerability struct {
	ID               string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	Severity         *Severity
	Title            string
	PURL             string
	// Targets maps component name to the platforms where this vulnerability was found.
	// e.g., {"Node.js": [ARM64, AMD64], "alpine:3.19": [AMD64]}
	Targets map[string][]*platform.Platform
}

// Severity represents vulnerability severity.
type Severity struct {
	value string
}

//nolint:gochecknoglobals // Severity enum pattern requires global variables
var (
	// SeverityUnknown represents unknown severity.
	SeverityUnknown = &Severity{trivy.Unknown}
	// SeverityLow represents low severity.
	SeverityLow = &Severity{trivy.Low}
	// SeverityMedium represents medium severity.
	SeverityMedium = &Severity{trivy.Medium}
	// SeverityHigh represents high severity.
	SeverityHigh = &Severity{trivy.High}
	// SeverityCritical represents critical severity.
	SeverityCritical = &Severity{trivy.Critical}
)

// ParseSeverity converts a severity string to a Severity pointer.
func ParseSeverity(s string) *Severity {
	switch s {
	case trivy.Critical:
		return SeverityCritical
	case trivy.High:
		return SeverityHigh
	case trivy.Medium:
		return SeverityMedium
	case trivy.Low:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// String returns the string representation of the severity.
func (s *Severity) String() string {
	return s.value
}

// MarshalJSON implements json.Marshaler for Severity.
func (s *Severity) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // Standard library JSON marshaling
	return json.Marshal(s.value)
}

// UnmarshalJSON implements json.Unmarshaler for Severity.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf(
			"%w: %w %q (valid: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)",
			fault.ErrInvalidArgument,
			err,
			str,
		)
	}

	normalized := strings.ToUpper(str)
	if normalized != SeverityUnknown.value &&
		normalized != SeverityLow.value &&
		normalized != SeverityMedium.value &&
		normalized != SeverityHigh.value &&
		normalized != SeverityCritical.value {
		return fmt.Errorf("%w: %q (valid: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)", fault.ErrInvalidArgument, str)
	}

	s.value = normalized

	return nil
}
