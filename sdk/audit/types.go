package audit

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/farcloser/quark/dev/core"
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

// SetSeverityCheckStrict provides a strict default basis for auditing.
//
//nolint:gochecknoglobals // Preset sets require global variables
var SetSeverityCheckStrict = []SeverityCheck{
	{
		Levels: []*Severity{
			SeverityFatal,
			SeverityWarn,
		},
		Action: ActionError,
	},
	{
		Levels: []*Severity{
			SeverityInfo,
		},
		Action: ActionWarn,
	},
}

// SetSeverityCheckRecommended provides a balanced default basis for auditing.
//
//nolint:gochecknoglobals // Preset sets require global variables
var SetSeverityCheckRecommended = []SeverityCheck{
	{
		Levels: []*Severity{
			SeverityFatal,
		},
		Action: ActionError,
	},
	{
		Levels: []*Severity{
			SeverityWarn,
		},
		Action: ActionWarn,
	},
}

// SetSeverityCheckLax provides a very lax, inform only basis for auditing.
//
//nolint:gochecknoglobals // Preset sets require global variables
var SetSeverityCheckLax = []SeverityCheck{
	{
		Levels: []*Severity{
			SeverityFatal,
		},
		Action: ActionWarn,
	},
}

// Options configures audit behavior.
type Options struct {
	SeverityChecks []SeverityCheck // Optional - level checks (default: FATAL+WARN error)
	Ignore         []string        // Dockle checks to ignore (e.g., "CIS-DI-0005")
	Format         *Format         // Optional - output format (default: table)
}

// SeverityCheck represents a level check with an action.
type SeverityCheck struct {
	Levels []*Severity `json:"levels,omitempty"`
	Action *Action     `json:"action,omitempty"`
}

// Severity represents dockle issue level.
type Severity struct {
	value string
}

// Dockle level constants.
const (
	severityFatal = "FATAL"
	severityWarn  = "WARN"
	severityInfo  = "INFO"
)

//nolint:gochecknoglobals // Severity enum pattern requires global variables
var (
	// SeverityFatal represents fatal level issues.
	SeverityFatal = &Severity{severityFatal}
	// SeverityWarn represents warning level issues.
	SeverityWarn = &Severity{severityWarn}
	// SeverityInfo represents info level issues.
	SeverityInfo = &Severity{severityInfo}
)

// String returns the string representation of the level.
func (l *Severity) String() string {
	return l.value
}

// MarshalJSON implements json.Marshaler for Severity.
func (l *Severity) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // Standard library JSON marshaling
	return json.Marshal(l.value)
}

// UnmarshalJSON implements json.Unmarshaler for Severity.
func (l *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("%w: %w %q (valid: FATAL, WARN, INFO)", ErrArgumentInvalidLevel, err, str)
	}

	normalized := strings.ToUpper(str)
	if normalized != severityFatal &&
		normalized != severityWarn &&
		normalized != severityInfo {
		return fmt.Errorf("%w: %q (valid: FATAL, WARN, INFO)", ErrArgumentInvalidLevel, str)
	}

	l.value = normalized

	return nil
}
