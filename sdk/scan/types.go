package scan

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/farcloser/quark/dev/shared"
	"github.com/farcloser/quark/internal/trivy"
)

// Action is an alias for shared.Action for user convenience.
type Action = shared.Action

// Action constants aliased from shared package.
//
//nolint:gochecknoglobals // Action enum pattern requires global variables
var (
	ActionError = shared.ActionError
	ActionWarn  = shared.ActionWarn
	ActionInfo  = shared.ActionInfo
	ActionDebug = shared.ActionDebug
)

// Format is an alias for shared.Format for user convenience.
type Format = shared.Format

// Format constants aliased from shared package.
//
//nolint:gochecknoglobals // Format enum pattern requires global variables
var (
	FormatTable = shared.FormatTable
	FormatJSON  = shared.FormatJSON
	FormatSARIF = shared.FormatSARIF
)

// SetSeverityCheckStrict provides a strict default basis for scanning.
//
//nolint:gochecknoglobals // Preset configuration for user convenience
var SetSeverityCheckStrict = []SeverityCheck{
	{
		Severities: []*Severity{
			SeverityCritical,
			SeverityHigh,
		},
		Action: ActionError,
	},
	{
		Severities: []*Severity{
			SeverityMedium,
		},
		Action: ActionWarn,
	},
}

// SetSeverityCheckRecommended provides a balanced default basis for scanning.
//
//nolint:gochecknoglobals // Preset configuration for user convenience
var SetSeverityCheckRecommended = []SeverityCheck{
	{
		Severities: []*Severity{
			SeverityCritical,
		},
		Action: ActionError,
	},
	{
		Severities: []*Severity{
			SeverityHigh,
		},
		Action: ActionWarn,
	},
}

// SetSeverityCheckLax provides a very lax, inform only basis for scanning.
//
//nolint:gochecknoglobals // Preset configuration for user convenience
var SetSeverityCheckLax = []SeverityCheck{
	{
		Severities: []*Severity{
			SeverityCritical,
		},
		Action: ActionWarn,
	},
}

// Options contains configuration for vulnerability scanning.
type Options struct {
	SeverityChecks []SeverityCheck // Optional - severity checks (default: HIGH+CRITICAL error)
	Ignore         []string        // CVE IDs to ignore (e.g., "CVE-2022-41723")
	Format         *Format         // Optional - output format (default: table)
}

// SeverityCheck represents a severity check with an action.
type SeverityCheck struct {
	Severities []*Severity `json:"severities,omitempty"`
	Action     *Action     `json:"action,omitempty"`
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
			ErrArgumentInvalidSeverity,
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
		return fmt.Errorf("%w: %q (valid: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)", ErrArgumentInvalidSeverity, str)
	}

	s.value = normalized

	return nil
}
