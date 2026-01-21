package format_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/farcloser/quark/pkg/dev/format"
	"github.com/farcloser/quark/pkg/fault"
)

func TestDisplay_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		display  *format.Display
		expected string
	}{
		{format.DisplayTable, "table"},
		{format.DisplayJSON, "json"},
		{format.DisplaySARIF, "sarif"},
	}

	for _, tc := range tests {
		if tc.display.String() != tc.expected {
			t.Errorf("expected %q, got %q", tc.expected, tc.display.String())
		}
	}
}

func TestDisplay_MarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		display  *format.Display
		expected string
	}{
		{format.DisplayTable, `"table"`},
		{format.DisplayJSON, `"json"`},
		{format.DisplaySARIF, `"sarif"`},
	}

	for _, tc := range tests {
		data, err := json.Marshal(tc.display)
		if err != nil {
			t.Fatalf("MarshalJSON failed: %v", err)
		}

		if string(data) != tc.expected {
			t.Errorf("expected %s, got %s", tc.expected, string(data))
		}
	}
}

func TestDisplay_UnmarshalJSON_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{`"table"`, "table"},
		{`"json"`, "json"},
		{`"sarif"`, "sarif"},
		// Case insensitive
		{`"TABLE"`, "table"},
		{`"JSON"`, "json"},
		{`"SARIF"`, "sarif"},
		{`"Table"`, "table"},
		{`"Json"`, "json"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			var d format.Display
			if err := json.Unmarshal([]byte(tc.input), &d); err != nil {
				t.Fatalf("UnmarshalJSON failed: %v", err)
			}

			if d.String() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, d.String())
			}
		})
	}
}

func TestDisplay_UnmarshalJSON_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"unknown format", `"xml"`},
		{"empty string", `""`},
		{"number", `123`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var d format.Display

			err := json.Unmarshal([]byte(tc.input), &d)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, fault.ErrInvalidArgument) {
				t.Errorf("expected fault.ErrInvalidArgument, got %v", err)
			}
		})
	}
}

func TestDisplay_RoundTrip(t *testing.T) {
	t.Parallel()

	displays := []*format.Display{
		format.DisplayTable,
		format.DisplayJSON,
		format.DisplaySARIF,
	}

	for _, original := range displays {
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("MarshalJSON failed: %v", err)
		}

		var decoded format.Display
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("UnmarshalJSON failed: %v", err)
		}

		if decoded.String() != original.String() {
			t.Errorf("round-trip failed: expected %q, got %q", original.String(), decoded.String())
		}
	}
}
