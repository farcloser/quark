package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Timeout is optional.
func TestScanBuilder_Build(t *testing.T) {
	t.Parallel()

	sourceImage, err := sdk.NewImage("alpine").
		Version("3.20").
		Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	tests := []struct {
		name    string
		build   func(*sdk.Plan) (*sdk.Scan, error)
		wantErr error
	}{
		{
			name: "valid scan with just source",
			build: func(plan *sdk.Plan) (*sdk.Scan, error) {
				return plan.Scan("test-scan").
					Source(sourceImage).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid scan with explicit severity",
			build: func(plan *sdk.Plan) (*sdk.Scan, error) {
				return plan.Scan("test-scan-severity").
					Source(sourceImage).
					Severity(sdk.SeverityCritical).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid scan with multiple severities",
			build: func(plan *sdk.Plan) (*sdk.Scan, error) {
				return plan.Scan("test-scan-multi").
					Source(sourceImage).
					Severity(sdk.SeverityCritical, sdk.ActionError).
					Severity(sdk.SeverityHigh, sdk.ActionWarn).
					Severity(sdk.SeverityMedium, sdk.ActionInfo).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid scan with format",
			build: func(plan *sdk.Plan) (*sdk.Scan, error) {
				return plan.Scan("test-scan-format").
					Source(sourceImage).
					Format(sdk.FormatJSON).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "missing source image",
			build: func(plan *sdk.Plan) (*sdk.Scan, error) {
				return plan.Scan("test-scan-no-source").
					Build()
			},
			wantErr: sdk.ErrScanImageRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")
			scan, err := tt.build(plan)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Build() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Build() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("Build() unexpected error = %v", err)

				return
			}

			if scan == nil {
				t.Error("Build() returned nil scan with nil error")
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
