package trivy_test

import (
	"log/slog"
	"testing"

	"github.com/farcloser/quark/internal/trivy"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// INTENTION: NewScanner should create a valid scanner when trivy can be installed.
func TestNewScanner(t *testing.T) {
	t.Parallel()

	scanner, err := trivy.NewScanner(t.Context(), discardLogger())
	if err != nil {
		t.Skipf("Skipping test: trivy installation failed: %v", err)
	}

	if scanner == nil {
		t.Fatal("NewScanner() returned nil scanner with nil error")
	}
}

// INTENTION: Severity constants should have expected string values.
func TestSeverityConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity string
		want     string
	}{
		{
			name:     "unknown severity",
			severity: trivy.Unknown,
			want:     "UNKNOWN",
		},
		{
			name:     "low severity",
			severity: trivy.Low,
			want:     "LOW",
		},
		{
			name:     "medium severity",
			severity: trivy.Medium,
			want:     "MEDIUM",
		},
		{
			name:     "high severity",
			severity: trivy.High,
			want:     "HIGH",
		},
		{
			name:     "critical severity",
			severity: trivy.Critical,
			want:     "CRITICAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.severity != tt.want {
				t.Errorf("Severity = %q, want %q", tt.severity, tt.want)
			}
		})
	}
}
