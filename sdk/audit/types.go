package audit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Options configures audit behavior.
type Options struct {
	Ignore []string // Dockle checks to ignore (e.g., "CIS-DI-0005")
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
