package format_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/farcloser/quark/pkg/dev/format"
	"github.com/farcloser/quark/pkg/fault"
)

func TestSeverity_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		severity *format.Severity
		expected string
	}{
		{format.Error, "error"},
		{format.Warn, "warn"},
		{format.Info, "info"},
		{format.Debug, "debug"},
	}

	for _, tc := range tests {
		if tc.severity.String() != tc.expected {
			t.Errorf("expected %q, got %q", tc.expected, tc.severity.String())
		}
	}
}

func TestSeverity_MarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		severity *format.Severity
		expected string
	}{
		{format.Error, `"error"`},
		{format.Warn, `"warn"`},
		{format.Info, `"info"`},
		{format.Debug, `"debug"`},
	}

	for _, tc := range tests {
		data, err := json.Marshal(tc.severity)
		if err != nil {
			t.Fatalf("MarshalJSON failed: %v", err)
		}

		if string(data) != tc.expected {
			t.Errorf("expected %s, got %s", tc.expected, string(data))
		}
	}
}

func TestSeverity_UnmarshalJSON_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{`"error"`, "error"},
		{`"warn"`, "warn"},
		{`"info"`, "info"},
		{`"debug"`, "debug"},
		// Case insensitive
		{`"ERROR"`, "error"},
		{`"WARN"`, "warn"},
		{`"INFO"`, "info"},
		{`"DEBUG"`, "debug"},
		{`"Error"`, "error"},
		{`"Warn"`, "warn"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			var s format.Severity
			if err := json.Unmarshal([]byte(tc.input), &s); err != nil {
				t.Fatalf("UnmarshalJSON failed: %v", err)
			}

			if s.String() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, s.String())
			}
		})
	}
}

func TestSeverity_UnmarshalJSON_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"unknown severity", `"critical"`},
		{"empty string", `""`},
		{"number", `123`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var s format.Severity

			err := json.Unmarshal([]byte(tc.input), &s)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, fault.ErrInvalidArgument) {
				t.Errorf("expected fault.ErrInvalidArgument, got %v", err)
			}
		})
	}
}

func TestSeverity_RoundTrip(t *testing.T) {
	t.Parallel()

	severities := []*format.Severity{
		format.Error,
		format.Warn,
		format.Info,
		format.Debug,
	}

	for _, original := range severities {
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("MarshalJSON failed: %v", err)
		}

		var decoded format.Severity
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("UnmarshalJSON failed: %v", err)
		}

		if decoded.String() != original.String() {
			t.Errorf("round-trip failed: expected %q, got %q", original.String(), decoded.String())
		}
	}
}
