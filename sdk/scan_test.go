package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Timeout is optional.
func TestNewScan(t *testing.T) {
	t.Parallel()

	sourceImage, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "alpine",
		Version: "3.20",
		Digest:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	tests := []struct {
		name    string
		args    *sdk.ScanArgs
		wantErr error
	}{
		{
			name: "valid scan with just source",
			args: &sdk.ScanArgs{
				Description: "test-scan",
				Source:      sourceImage,
			},
			wantErr: nil,
		},
		{
			name: "valid scan with explicit severity",
			args: &sdk.ScanArgs{
				Description: "test-scan-severity",
				Source:      sourceImage,
				SeverityChecks: []sdk.ScanSeverityCheck{
					{Threshold: sdk.SeverityCritical, Action: sdk.ActionError},
				},
			},
			wantErr: nil,
		},
		{
			name: "valid scan with multiple severities",
			args: &sdk.ScanArgs{
				Description: "test-scan-multi",
				Source:      sourceImage,
				SeverityChecks: []sdk.ScanSeverityCheck{
					{Threshold: sdk.SeverityCritical, Action: sdk.ActionError},
					{Threshold: sdk.SeverityHigh, Action: sdk.ActionWarn},
					{Threshold: sdk.SeverityMedium, Action: sdk.ActionInfo},
				},
			},
			wantErr: nil,
		},
		{
			name: "valid scan with format",
			args: &sdk.ScanArgs{
				Description: "test-scan-format",
				Source:      sourceImage,
				Format:      sdk.FormatJSON,
			},
			wantErr: nil,
		},
		{
			name: "missing source image",
			args: &sdk.ScanArgs{
				Description: "test-scan-no-source",
			},
			wantErr: sdk.ErrScanImageRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")
			scan, err := plan.Scan(tt.args)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Scan() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Scan() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("Scan() unexpected error = %v", err)

				return
			}

			if scan == nil {
				t.Error("Scan() returned nil scan with nil error")
			}
		})
	}
}

// INTENTION: Only valid severity values should be accepted.
func TestScanSeverity_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		json    string
		wantErr error
	}{
		{
			name:    "valid UNKNOWN",
			json:    `"UNKNOWN"`,
			wantErr: nil,
		},
		{
			name:    "valid LOW",
			json:    `"LOW"`,
			wantErr: nil,
		},
		{
			name:    "valid MEDIUM",
			json:    `"MEDIUM"`,
			wantErr: nil,
		},
		{
			name:    "valid HIGH",
			json:    `"HIGH"`,
			wantErr: nil,
		},
		{
			name:    "valid CRITICAL",
			json:    `"CRITICAL"`,
			wantErr: nil,
		},
		{
			name:    "valid lowercase (normalized)",
			json:    `"critical"`,
			wantErr: nil,
		},
		{
			name:    "valid mixed case (normalized)",
			json:    `"CrItIcAl"`,
			wantErr: nil,
		},
		{
			name:    "invalid severity value",
			json:    `"ULTRA_CRITICAL"`,
			wantErr: sdk.ErrInvalidScanSeverity,
		},
		{
			name:    "empty string",
			json:    `""`,
			wantErr: sdk.ErrInvalidScanSeverity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var severity sdk.ScanSeverity
			err := severity.UnmarshalJSON([]byte(tt.json))

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("UnmarshalJSON() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("UnmarshalJSON() unexpected error = %v", err)
			}
		})
	}
}

// INTENTION: Only valid action values should be accepted.
func TestScanAction_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		json    string
		wantErr error
	}{
		{
			name:    "valid error",
			json:    `"error"`,
			wantErr: nil,
		},
		{
			name:    "valid warn",
			json:    `"warn"`,
			wantErr: nil,
		},
		{
			name:    "valid info",
			json:    `"info"`,
			wantErr: nil,
		},
		{
			name:    "valid uppercase (normalized)",
			json:    `"ERROR"`,
			wantErr: nil,
		},
		{
			name:    "invalid action value",
			json:    `"panic"`,
			wantErr: sdk.ErrInvalidScanAction,
		},
		{
			name:    "empty string",
			json:    `""`,
			wantErr: sdk.ErrInvalidScanAction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var action sdk.ScanAction
			err := action.UnmarshalJSON([]byte(tt.json))

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("UnmarshalJSON() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("UnmarshalJSON() unexpected error = %v", err)
			}
		})
	}
}

// INTENTION: Only valid format values should be accepted.
func TestScanFormat_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		json    string
		wantErr error
	}{
		{
			name:    "valid table",
			json:    `"table"`,
			wantErr: nil,
		},
		{
			name:    "valid json",
			json:    `"json"`,
			wantErr: nil,
		},
		{
			name:    "valid sarif",
			json:    `"sarif"`,
			wantErr: nil,
		},
		{
			name:    "valid uppercase (normalized)",
			json:    `"TABLE"`,
			wantErr: nil,
		},
		{
			name:    "invalid format value",
			json:    `"xml"`,
			wantErr: sdk.ErrInvalidScanFormat,
		},
		{
			name:    "empty string",
			json:    `""`,
			wantErr: sdk.ErrInvalidScanFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var format sdk.ScanFormat
			err := format.UnmarshalJSON([]byte(tt.json))

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("UnmarshalJSON() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("UnmarshalJSON() unexpected error = %v", err)
			}
		})
	}
}
