package format

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/farcloser/quark/pkg/fault"
)

// Display represents output format.
type Display struct {
	value string
}

//nolint:gochecknoglobals // Display enum pattern requires global variables
var (
	// DisplayTable represents table output.
	DisplayTable = &Display{"table"}
	// DisplayJSON represents JSON output.
	DisplayJSON = &Display{"json"}
	// DisplaySARIF represents DisplaySARIF output.
	DisplaySARIF = &Display{"sarif"}
)

// String returns the string representation of the format.
func (f *Display) String() string {
	return f.value
}

// MarshalJSON implements json.Marshaler for Display.
func (f *Display) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // Standard library JSON marshaling
	return json.Marshal(f.value)
}

// UnmarshalJSON implements json.Unmarshaler for Display.
func (f *Display) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("%w: %w %q (valid: table, json, sarif)", fault.ErrInvalidArgument, err, str)
	}

	// Normalize to lowercase
	normalized := strings.ToLower(str)

	if normalized != DisplayJSON.value &&
		normalized != DisplayTable.value &&
		normalized != DisplaySARIF.value {
		return fmt.Errorf("%w: %q (valid: table, json, sarif)", fault.ErrInvalidArgument, str)
	}

	f.value = normalized

	return nil
}
