package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Action represents how to handle issues at a severity/level threshold.
type Action struct {
	value string
}

//nolint:gochecknoglobals // Action enum pattern requires global variables
var (
	// ActionError causes operation to fail.
	ActionError = &Action{"error"}
	// ActionWarn logs issues as warnings without failing.
	ActionWarn = &Action{"warn"}
	// ActionInfo logs issues as info without failing.
	ActionInfo = &Action{"info"}
	// ActionDebug logs issues as debug without failing.
	ActionDebug = &Action{"debug"}
)

// ErrArgumentInvalidAction is returned when an invalid action is provided.
var ErrArgumentInvalidAction = errors.New("invalid action")

// String returns the string representation of the action.
func (a *Action) String() string {
	return a.value
}

// MarshalJSON implements json.Marshaler for Action.
func (a *Action) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // Standard library JSON marshaling
	return json.Marshal(a.value)
}

// UnmarshalJSON implements json.Unmarshaler for Action.
func (a *Action) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("%w: %w %q (valid: error, warn, info, debug)", ErrArgumentInvalidAction, err, str)
	}

	// Normalize to lowercase
	normalized := strings.ToLower(str)
	if normalized != ActionDebug.value &&
		normalized != ActionInfo.value &&
		normalized != ActionWarn.value &&
		normalized != ActionError.value {
		return fmt.Errorf("%w: %q (valid: error, warn, info, debug)", ErrArgumentInvalidAction, str)
	}

	a.value = normalized

	return nil
}
