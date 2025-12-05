package lint

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/farcloser/quark/dev/core"
	"github.com/farcloser/quark/internal/godolint"
)

// Action is an alias for core.Action for user convenience.
type Action = core.Action

// Action constants aliased from shared package.
//
//nolint:gochecknoglobals // Action enum pattern requires global variables
var (
	ActionError = core.ActionError
	ActionWarn  = core.ActionWarn
	ActionInfo  = core.ActionInfo
	ActionDebug = core.ActionDebug
)

// Format is an alias for core.Format for user convenience.
type Format = core.Format

// Format constants aliased from shared package.
//
//nolint:gochecknoglobals // Format enum pattern requires global variables
var (
	FormatTable = core.FormatTable
	FormatJSON  = core.FormatJSON
	FormatSARIF = core.FormatSARIF
)

// SetSeverityCheckStrict provides a strict default basis for linting.
//
//nolint:gochecknoglobals // Preset sets require global variables
var SetSeverityCheckStrict = []SeverityCheck{
	{
		Severities: []*Severity{
			SeverityError,
			SeverityWarning,
		},
		Action: ActionError,
	},
	{
		Severities: []*Severity{
			SeverityInfo,
		},
		Action: ActionWarn,
	},
}

// SetSeverityCheckRecommended provides a balanced default basis for linting.
//
//nolint:gochecknoglobals // Preset sets require global variables
var SetSeverityCheckRecommended = []SeverityCheck{
	{
		Severities: []*Severity{
			SeverityError,
		},
		Action: ActionError,
	},
	{
		Severities: []*Severity{
			SeverityWarning,
		},
		Action: ActionWarn,
	},
}

// SetSeverityCheckLax provides a very lax, inform only basis for linting.
//
//nolint:gochecknoglobals // Preset sets require global variables
var SetSeverityCheckLax = []SeverityCheck{
	{
		Severities: []*Severity{
			SeverityError,
		},
		Action: ActionWarn,
	},
}

// Options configures lint behavior.
type Options struct {
	SeverityChecks []SeverityCheck // Optional - severity checks (default: ERROR error, WARNING warn)
	Ignore         []string        // Rule codes to ignore (e.g., "DL3000", "SC2086")
	Format         *Format         // Optional - output format (default: table)
}

// SeverityCheck represents a severity check with an action.
type SeverityCheck struct {
	Severities []*Severity `json:"severities,omitempty"`
	Action     *Action     `json:"action,omitempty"`
}

// Severity represents godolint issue severity.
type Severity struct {
	value string
}

//nolint:gochecknoglobals // Severity enum pattern requires global variables
var (
	// SeverityError represents error severity issues.
	SeverityError = &Severity{string(godolint.SeverityError)}
	// SeverityWarning represents warning severity issues.
	SeverityWarning = &Severity{string(godolint.SeverityWarning)}
	// SeverityInfo represents info severity issues.
	SeverityInfo = &Severity{string(godolint.SeverityInfo)}
	// SeverityStyle represents style severity issues.
	SeverityStyle = &Severity{string(godolint.SeverityStyle)}
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
		return fmt.Errorf("%w: %w %q (valid: error, warning, info, style)", ErrArgumentInvalidSeverity, err, str)
	}

	normalized := strings.ToLower(str)
	if normalized != string(godolint.SeverityError) &&
		normalized != string(godolint.SeverityWarning) &&
		normalized != string(godolint.SeverityInfo) &&
		normalized != string(godolint.SeverityStyle) {
		return fmt.Errorf("%w: %q (valid: error, warning, info, style)", ErrArgumentInvalidSeverity, str)
	}

	s.value = normalized

	return nil
}
