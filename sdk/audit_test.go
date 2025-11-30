package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Timeout is optional.
func TestNewAudit(t *testing.T) {
	t.Parallel()

	sourceImage, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "alpine",
		Version: "3.20",
	})
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	tests := []struct {
		name    string
		args    *sdk.AuditArgs
		wantErr error
	}{
		{
			name: "valid audit with dockerfile only",
			args: &sdk.AuditArgs{
				Description: "test-audit-dockerfile",
				Dockerfile:  "/path/to/Dockerfile",
			},
			wantErr: nil,
		},
		{
			name: "valid audit with image only",
			args: &sdk.AuditArgs{
				Description: "test-audit-image",
				Source:      sourceImage,
			},
			wantErr: nil,
		},
		{
			name: "valid audit with both dockerfile and image",
			args: &sdk.AuditArgs{
				Description: "test-audit-both",
				Dockerfile:  "/path/to/Dockerfile",
				Source:      sourceImage,
			},
			wantErr: nil,
		},
		{
			name: "valid audit with explicit ruleset",
			args: &sdk.AuditArgs{
				Description: "test-audit-ruleset",
				Dockerfile:  "/path/to/Dockerfile",
				RuleSet:     sdk.RuleSetRecommended,
			},
			wantErr: nil,
		},
		{
			name: "valid audit with ignore checks",
			args: &sdk.AuditArgs{
				Description:  "test-audit-ignore",
				Dockerfile:   "/path/to/Dockerfile",
				IgnoreChecks: []string{"DKL-DI-0005", "DKL-DI-0006"},
			},
			wantErr: nil,
		},
		{
			name: "missing both dockerfile and image",
			args: &sdk.AuditArgs{
				Description: "test-audit-no-source",
			},
			wantErr: sdk.ErrAuditSourceRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")
			audit, err := plan.Audit(tt.args)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Audit() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Audit() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("Audit() unexpected error = %v", err)

				return
			}

			if audit == nil {
				t.Error("Audit() returned nil audit with nil error")
			}
		})
	}
}

// INTENTION: Only valid ruleset values should be accepted.
func TestAuditRuleSet_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		json    string
		wantErr error
	}{
		{
			name:    "valid strict",
			json:    `"strict"`,
			wantErr: nil,
		},
		{
			name:    "valid recommended",
			json:    `"recommended"`,
			wantErr: nil,
		},
		{
			name:    "valid minimal",
			json:    `"minimal"`,
			wantErr: nil,
		},
		{
			name:    "valid uppercase (normalized)",
			json:    `"STRICT"`,
			wantErr: nil,
		},
		{
			name:    "valid mixed case (normalized)",
			json:    `"Recommended"`,
			wantErr: nil,
		},
		{
			name:    "invalid ruleset value",
			json:    `"ultra-strict"`,
			wantErr: sdk.ErrInvalidAuditRuleSet,
		},
		{
			name:    "empty string",
			json:    `""`,
			wantErr: sdk.ErrInvalidAuditRuleSet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var ruleset sdk.AuditRuleSet
			err := ruleset.UnmarshalJSON([]byte(tt.json))

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
