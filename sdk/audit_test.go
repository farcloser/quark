//nolint:varnamelen,wsl
package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Timeout is optional.
func TestAuditBuilder_Build(t *testing.T) {
	t.Parallel()

	sourceImage, err := sdk.NewImage("alpine").
		Version("3.20").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	tests := []struct {
		name    string
		build   func(*sdk.Plan) (*sdk.Audit, error)
		wantErr error
	}{
		{
			name: "valid audit with dockerfile only",
			build: func(plan *sdk.Plan) (*sdk.Audit, error) {
				return plan.Audit("test-audit-dockerfile").
					Dockerfile("/path/to/Dockerfile").
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid audit with image only",
			build: func(plan *sdk.Plan) (*sdk.Audit, error) {
				return plan.Audit("test-audit-image").
					Source(sourceImage).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid audit with both dockerfile and image",
			build: func(plan *sdk.Plan) (*sdk.Audit, error) {
				return plan.Audit("test-audit-both").
					Dockerfile("/path/to/Dockerfile").
					Source(sourceImage).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid audit with explicit ruleset",
			build: func(plan *sdk.Plan) (*sdk.Audit, error) {
				return plan.Audit("test-audit-ruleset").
					Dockerfile("/path/to/Dockerfile").
					RuleSet(sdk.RuleSetRecommended).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid audit with ignore checks",
			build: func(plan *sdk.Plan) (*sdk.Audit, error) {
				return plan.Audit("test-audit-ignore").
					Dockerfile("/path/to/Dockerfile").
					IgnoreChecks("DKL-DI-0005", "DKL-DI-0006").
					Build()
			},
			wantErr: nil,
		},
		{
			name: "missing both dockerfile and image",
			build: func(plan *sdk.Plan) (*sdk.Audit, error) {
				return plan.Audit("test-audit-no-source").
					Build()
			},
			wantErr: sdk.ErrAuditSourceRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")
			audit, err := tt.build(plan)

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

			if audit == nil {
				t.Error("Build() returned nil audit with nil error")
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

// INTENTION: Multiple calls to IgnoreChecks should accumulate, not replace.
func TestAuditBuilder_IgnoreChecks(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan("test-plan")

	// Build audit with multiple IgnoreChecks calls
	audit, err := plan.Audit("test-audit").
		Dockerfile("/path/to/Dockerfile").
		IgnoreChecks("DKL-DI-0005").
		IgnoreChecks("DKL-DI-0006", "DKL-DI-0007").
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	if audit == nil {
		t.Fatal("Build() returned nil audit")
	}
	// Note: Cannot verify ignore checks directly (unexported field)
	// This test documents the intention - checks should accumulate
}
