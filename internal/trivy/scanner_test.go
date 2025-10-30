package trivy_test

import (
	"testing"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/trivy"
)

// INTENTION: NewScanner should create a valid scanner.
func TestNewScanner(t *testing.T) {
	t.Parallel()

	scanner := trivy.NewScanner(zerolog.Nop())

	if scanner == nil {
		t.Fatal("NewScanner() returned nil, want non-nil scanner")
	}
}

// INTENTION: ScanImage with empty reference should fail.
func TestScanner_ScanImage_EmptyReference(t *testing.T) {
	t.Parallel()

	scanner := trivy.NewScanner(zerolog.Nop())
	ctx := t.Context()

	severities := []trivy.Severity{trivy.SeverityHigh, trivy.SeverityCritical}

	result, err := scanner.ScanImage(ctx, "", severities, "json", "", "", "")

	// Should fail with empty reference
	// Note: Trivy will fail at scan execution, not at parse stage
	if err == nil {
		t.Error("ScanImage() error = nil, want error for empty reference")
	}

	if result != nil {
		t.Errorf("ScanImage() result = %v, want nil on error", result)
	}
}

// INTENTION: CheckThreshold should detect vulnerabilities matching severity.
func TestScanner_CheckThreshold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		result        *trivy.ScanResult
		severities    []trivy.Severity
		wantExceed    bool
		wantThreshold string
	}{
		{
			name: "no vulnerabilities",
			result: &trivy.ScanResult{
				Results: []trivy.Result{},
			},
			severities:    []trivy.Severity{trivy.SeverityCritical},
			wantExceed:    false,
			wantThreshold: "threshold not exceeded",
		},
		{
			name: "critical vulnerability exceeds critical threshold",
			result: &trivy.ScanResult{
				Results: []trivy.Result{
					{
						Target: "test-image",
						Vulnerabilities: []trivy.Vulnerability{
							{
								VulnerabilityID:  "CVE-2024-1234",
								PkgName:          "libtest",
								InstalledVersion: "1.0.0",
								FixedVersion:     "1.0.1",
								Severity:         "CRITICAL",
								Title:            "Test vulnerability",
							},
						},
					},
				},
			},
			severities:    []trivy.Severity{trivy.SeverityCritical},
			wantExceed:    true,
			wantThreshold: "threshold exceeded",
		},
		{
			name: "high vulnerability does not exceed critical threshold",
			result: &trivy.ScanResult{
				Results: []trivy.Result{
					{
						Target: "test-image",
						Vulnerabilities: []trivy.Vulnerability{
							{
								VulnerabilityID:  "CVE-2024-5678",
								PkgName:          "libtest",
								InstalledVersion: "1.0.0",
								FixedVersion:     "1.0.1",
								Severity:         "HIGH",
								Title:            "Test vulnerability",
							},
						},
					},
				},
			},
			severities:    []trivy.Severity{trivy.SeverityCritical},
			wantExceed:    false,
			wantThreshold: "threshold not exceeded",
		},
		{
			name: "high vulnerability exceeds high+critical threshold",
			result: &trivy.ScanResult{
				Results: []trivy.Result{
					{
						Target: "test-image",
						Vulnerabilities: []trivy.Vulnerability{
							{
								VulnerabilityID:  "CVE-2024-5678",
								PkgName:          "libtest",
								InstalledVersion: "1.0.0",
								FixedVersion:     "1.0.1",
								Severity:         "HIGH",
								Title:            "Test vulnerability",
							},
						},
					},
				},
			},
			severities:    []trivy.Severity{trivy.SeverityHigh, trivy.SeverityCritical},
			wantExceed:    true,
			wantThreshold: "threshold exceeded",
		},
		{
			name: "low vulnerability does not exceed high threshold",
			result: &trivy.ScanResult{
				Results: []trivy.Result{
					{
						Target: "test-image",
						Vulnerabilities: []trivy.Vulnerability{
							{
								VulnerabilityID:  "CVE-2024-9999",
								PkgName:          "libtest",
								InstalledVersion: "1.0.0",
								FixedVersion:     "1.0.1",
								Severity:         "LOW",
								Title:            "Test vulnerability",
							},
						},
					},
				},
			},
			severities:    []trivy.Severity{trivy.SeverityHigh},
			wantExceed:    false,
			wantThreshold: "threshold not exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanner := trivy.NewScanner(zerolog.Nop())
			exceeded := scanner.CheckThreshold(tt.result, tt.severities)

			if exceeded != tt.wantExceed {
				t.Errorf("CheckThreshold() = %v, want %v (%s)", exceeded, tt.wantExceed, tt.wantThreshold)
			}
		})
	}
}

// INTENTION: FormatOutput should support table and JSON formats.
func TestScanner_FormatOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		format  string
		result  *trivy.ScanResult
		wantErr bool
	}{
		{
			name:   "table format",
			format: "table",
			result: &trivy.ScanResult{
				Results: []trivy.Result{
					{
						Target: "test-image",
						Vulnerabilities: []trivy.Vulnerability{
							{
								VulnerabilityID:  "CVE-2024-1234",
								PkgName:          "libtest",
								InstalledVersion: "1.0.0",
								FixedVersion:     "1.0.1",
								Severity:         "HIGH",
								Title:            "Test vulnerability",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "json format",
			format: "json",
			result: &trivy.ScanResult{
				Results: []trivy.Result{
					{
						Target: "test-image",
						Vulnerabilities: []trivy.Vulnerability{
							{
								VulnerabilityID:  "CVE-2024-1234",
								PkgName:          "libtest",
								InstalledVersion: "1.0.0",
								FixedVersion:     "1.0.1",
								Severity:         "HIGH",
								Title:            "Test vulnerability",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "unsupported format",
			format: "xml",
			result: &trivy.ScanResult{
				Results: []trivy.Result{},
			},
			wantErr: true,
		},
		{
			name:   "empty format",
			format: "",
			result: &trivy.ScanResult{
				Results: []trivy.Result{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanner := trivy.NewScanner(zerolog.Nop())
			output, err := scanner.FormatOutput(tt.result, tt.format)

			if (err != nil) != tt.wantErr {
				t.Errorf("FormatOutput() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && output == "" {
				t.Error("FormatOutput() output is empty, want non-empty output")
			}

			if tt.wantErr && output != "" {
				t.Errorf("FormatOutput() output = %q, want empty on error", output)
			}
		})
	}
}

// INTENTION: FormatOutput table format should produce human-readable output.
func TestScanner_FormatOutput_TableFormat(t *testing.T) {
	t.Parallel()

	result := &trivy.ScanResult{
		Results: []trivy.Result{
			{
				Target: "alpine:latest",
				Vulnerabilities: []trivy.Vulnerability{
					{
						VulnerabilityID:  "CVE-2024-1234",
						PkgName:          "libssl",
						InstalledVersion: "1.1.1",
						FixedVersion:     "1.1.2",
						Severity:         "CRITICAL",
						Title:            "Buffer overflow in libssl",
					},
				},
			},
		},
	}

	scanner := trivy.NewScanner(zerolog.Nop())
	output, err := scanner.FormatOutput(result, "table")
	if err != nil {
		t.Fatalf("FormatOutput() error = %v, want nil", err)
	}

	// Check that output contains expected elements
	expectedSubstrings := []string{
		"CVE-2024-1234",
		"libssl",
		"CRITICAL",
		"Buffer overflow",
		"1.1.1",
		"1.1.2",
	}

	for _, substr := range expectedSubstrings {
		if !contains(output, substr) {
			t.Errorf("FormatOutput() output missing %q", substr)
		}
	}
}

// INTENTION: FormatOutput JSON format should produce valid JSON.
func TestScanner_FormatOutput_JSONFormat(t *testing.T) {
	t.Parallel()

	result := &trivy.ScanResult{
		Results: []trivy.Result{
			{
				Target: "alpine:latest",
				Vulnerabilities: []trivy.Vulnerability{
					{
						VulnerabilityID:  "CVE-2024-1234",
						PkgName:          "libssl",
						InstalledVersion: "1.1.1",
						FixedVersion:     "1.1.2",
						Severity:         "CRITICAL",
						Title:            "Buffer overflow in libssl",
					},
				},
			},
		},
	}

	scanner := trivy.NewScanner(zerolog.Nop())
	output, err := scanner.FormatOutput(result, "json")
	if err != nil {
		t.Fatalf("FormatOutput() error = %v, want nil", err)
	}

	// JSON output should start with { and end with }
	if len(output) < 2 || output[0] != '{' || output[len(output)-1] != '}' {
		t.Error("FormatOutput() JSON output is not properly formatted")
	}

	// Should contain key fields as JSON keys
	expectedJSONKeys := []string{
		"\"Results\"",
		"\"Target\"",
		"\"Vulnerabilities\"",
		"\"VulnerabilityID\"",
	}

	for _, key := range expectedJSONKeys {
		if !contains(output, key) {
			t.Errorf("FormatOutput() JSON output missing key %q", key)
		}
	}
}

// INTENTION: Severity constants should have expected string values.
func TestSeverityConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity trivy.Severity
		want     string
	}{
		{
			name:     "unknown severity",
			severity: trivy.SeverityUnknown,
			want:     "UNKNOWN",
		},
		{
			name:     "low severity",
			severity: trivy.SeverityLow,
			want:     "LOW",
		},
		{
			name:     "medium severity",
			severity: trivy.SeverityMedium,
			want:     "MEDIUM",
		},
		{
			name:     "high severity",
			severity: trivy.SeverityHigh,
			want:     "HIGH",
		},
		{
			name:     "critical severity",
			severity: trivy.SeverityCritical,
			want:     "CRITICAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if string(tt.severity) != tt.want {
				t.Errorf("Severity = %q, want %q", tt.severity, tt.want)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}

	return false
}
