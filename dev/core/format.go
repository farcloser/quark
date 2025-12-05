package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Format represents output format.
type Format struct {
	value string
}

//nolint:gochecknoglobals // Format enum pattern requires global variables
var (
	// FormatTable represents table output.
	FormatTable = &Format{"table"}
	// FormatJSON represents JSON output.
	FormatJSON = &Format{"json"}
	// FormatSARIF represents SARIF output.
	FormatSARIF = &Format{"sarif"}
)

// ErrArgumentInvalidFormat is returned when an invalid format is provided.
var ErrArgumentInvalidFormat = errors.New("invalid format")

// String returns the string representation of the format.
func (f *Format) String() string {
	return f.value
}

// MarshalJSON implements json.Marshaler for Format.
func (f *Format) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // Standard library JSON marshaling
	return json.Marshal(f.value)
}

// UnmarshalJSON implements json.Unmarshaler for Format.
func (f *Format) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("%w: %w %q (valid: table, json, sarif)", ErrArgumentInvalidFormat, err, str)
	}

	// Normalize to lowercase
	normalized := strings.ToLower(str)

	if normalized != FormatJSON.value &&
		normalized != FormatTable.value &&
		normalized != FormatSARIF.value {
		return fmt.Errorf("%w: %q (valid: table, json, sarif)", ErrArgumentInvalidFormat, str)
	}

	f.value = normalized

	return nil
}
