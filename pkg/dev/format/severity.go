package format

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/farcloser/quark/pkg/fault"
)

// Severity represents how to handle issues at a severity/level threshold.
type Severity struct {
	value string
}

//nolint:gochecknoglobals // Severity enum pattern requires global variables
var (
	// Error causes operation to fail.
	Error = &Severity{"error"}
	// Warn logs issues as warnings without failing.
	Warn = &Severity{"warn"}
	// Info logs issues as info without failing.
	Info = &Severity{"info"}
	// Debug logs issues as debug without failing.
	Debug = &Severity{"debug"}
)

// String returns the string representation of the action.
func (a *Severity) String() string {
	return a.value
}

// MarshalJSON implements json.Marshaler for Severity.
func (a *Severity) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // Standard library JSON marshaling
	return json.Marshal(a.value)
}

// UnmarshalJSON implements json.Unmarshaler for Severity.
func (a *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("%w: %w %q (valid: error, warn, info, debug)", fault.ErrInvalidArgument, err, str)
	}

	// Normalize to lowercase
	normalized := strings.ToLower(str)
	if normalized != Debug.value &&
		normalized != Info.value &&
		normalized != Warn.value &&
		normalized != Error.value {
		return fmt.Errorf("%w: %q (valid: error, warn, info, debug)", fault.ErrInvalidArgument, str)
	}

	a.value = normalized

	return nil
}
