package dockle_test

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/farcloser/quark/internal/a_deprecated/dockle"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// INTENTION: NewScanner should create a valid scanner when dockle can be installed.
func TestNewScanner(t *testing.T) {
	t.Parallel()

	scanner, err := dockle.NewScanner(t.Context(), discardLogger())
	if err != nil {
		t.Skipf("Skipping test: dockle installation failed: %v", err)
	}

	if scanner == nil {
		t.Fatal("NewScanner() returned nil scanner with nil error")
	}
}

// INTENTION: Detail struct should correctly marshal/unmarshal JSON.
func TestDetailJSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := dockle.Detail{
		Code:   "CIS-DI-0001",
		Title:  "Create a user for the container",
		Level:  "WARN",
		Alerts: []string{"Last user should not be root"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal Detail: %v", err)
	}

	var decoded dockle.Detail
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal Detail: %v", err)
	}

	if decoded.Code != original.Code {
		t.Errorf("Code = %q, want %q", decoded.Code, original.Code)
	}

	if decoded.Title != original.Title {
		t.Errorf("Title = %q, want %q", decoded.Title, original.Title)
	}

	if decoded.Level != original.Level {
		t.Errorf("Level = %q, want %q", decoded.Level, original.Level)
	}

	if len(decoded.Alerts) != len(original.Alerts) {
		t.Fatalf("Alerts length = %d, want %d", len(decoded.Alerts), len(original.Alerts))
	}

	if decoded.Alerts[0] != original.Alerts[0] {
		t.Errorf("Alerts[0] = %q, want %q", decoded.Alerts[0], original.Alerts[0])
	}
}

// INTENTION: ScanResult struct should correctly marshal/unmarshal JSON.
func TestScanResultJSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := dockle.ScanResult{
		Details: []dockle.Detail{
			{
				Code:   "CIS-DI-0001",
				Title:  "Create a user for the container",
				Level:  "WARN",
				Alerts: []string{"Last user should not be root"},
			},
			{
				Code:   "CIS-DI-0005",
				Title:  "Enable content trust for Docker",
				Level:  "INFO",
				Alerts: []string{"export DOCKER_CONTENT_TRUST=1"},
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal ScanResult: %v", err)
	}

	var decoded dockle.ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ScanResult: %v", err)
	}

	if len(decoded.Details) != len(original.Details) {
		t.Fatalf("Details length = %d, want %d", len(decoded.Details), len(original.Details))
	}

	for i, detail := range decoded.Details {
		if detail.Code != original.Details[i].Code {
			t.Errorf("Details[%d].Code = %q, want %q", i, detail.Code, original.Details[i].Code)
		}

		if detail.Title != original.Details[i].Title {
			t.Errorf("Details[%d].Title = %q, want %q", i, detail.Title, original.Details[i].Title)
		}

		if detail.Level != original.Details[i].Level {
			t.Errorf("Details[%d].Level = %q, want %q", i, detail.Level, original.Details[i].Level)
		}
	}
}

// INTENTION: Empty ScanResult should marshal to valid JSON.
func TestEmptyScanResultJSON(t *testing.T) {
	t.Parallel()

	original := dockle.ScanResult{}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal empty ScanResult: %v", err)
	}

	var decoded dockle.ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal empty ScanResult: %v", err)
	}

	if len(decoded.Details) != 0 {
		t.Errorf("Expected nil or empty Details, got %d items", len(decoded.Details))
	}
}
