//nolint:varnamelen,wsl
package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Digest is optional (but recommended for verification).
func TestVersionCheckBuilder_Build(t *testing.T) {
	t.Parallel()

	imageWithVersion, err := sdk.NewImage("timberio/vector").
		Version("0.50.0-distroless-static").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test image with version: %v", err)
	}

	imageWithVersionAndDigest, err := sdk.NewImage("timberio/vector").
		Version("0.50.0-distroless-static").
		Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test image with version and digest: %v", err)
	}

	imageWithoutVersion, err := sdk.NewImage("timberio/vector").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test image without version: %v", err)
	}

	tests := []struct {
		name    string
		build   func(*sdk.Plan) (*sdk.VersionCheck, error)
		wantErr error
	}{
		{
			name: "valid version check with version only",
			build: func(plan *sdk.Plan) (*sdk.VersionCheck, error) {
				return plan.VersionCheck("test-version").
					Source(imageWithVersion).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid version check with version and digest",
			build: func(plan *sdk.Plan) (*sdk.VersionCheck, error) {
				return plan.VersionCheck("test-version-digest").
					Source(imageWithVersionAndDigest).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "missing source image",
			build: func(plan *sdk.Plan) (*sdk.VersionCheck, error) {
				return plan.VersionCheck("test-version-no-source").
					Build()
			},
			wantErr: sdk.ErrVersionCheckImageRequired,
		},
		{
			name: "source image without version",
			build: func(plan *sdk.Plan) (*sdk.VersionCheck, error) {
				return plan.VersionCheck("test-version-no-version").
					Source(imageWithoutVersion).
					Build()
			},
			wantErr: sdk.ErrVersionCheckVersionRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")
			check, err := tt.build(plan)

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

			if check == nil {
				t.Error("Build() returned nil check with nil error")
			}
		})
	}
}

// INTENTION: Getters should return empty values before execution.
func TestVersionCheck_Getters(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan("test-plan")

	imageWithVersion, err := sdk.NewImage("timberio/vector").
		Version("0.50.0-distroless-static").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	check, err := plan.VersionCheck("test-version").
		Source(imageWithVersion).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Before execution, all getters should return zero values
	if check.CurrentVersion() != "" {
		t.Errorf("CurrentVersion() before execution = %q, want empty", check.CurrentVersion())
	}

	if check.LatestVersion() != "" {
		t.Errorf("LatestVersion() before execution = %q, want empty", check.LatestVersion())
	}

	if check.LatestDigest() != "" {
		t.Errorf("LatestDigest() before execution = %q, want empty", check.LatestDigest())
	}

	if check.UpdateAvailable() {
		t.Error("UpdateAvailable() before execution = true, want false")
	}

	if check.Executed() {
		t.Error("Executed() before execution = true, want false")
	}
}

// INTENTION: Credentials should be looked up from plan's registry collection by domain.
func TestVersionCheck_RegistryLookup(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan("test-plan")

	// Add registry credentials to plan
	_, err := plan.Registry("ghcr.io").
		Username("testuser").
		Password("testpass").
		Build()
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// Image uses ghcr.io - should find registry credentials
	imageWithVersion, err := sdk.NewImage("my-org/my-app").
		Domain("ghcr.io").
		Version("1.0.0").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	// Build should succeed and automatically lookup ghcr.io credentials
	check, err := plan.VersionCheck("test-version").
		Source(imageWithVersion).
		Build()
	if err != nil {
		t.Errorf("Build() error = %v, want nil", err)
	}

	if check == nil {
		t.Error("Build() returned nil check")
	}
	// Note: Cannot verify credentials were found (unexported fields)
	// This test documents the intention - credentials should be looked up
}
