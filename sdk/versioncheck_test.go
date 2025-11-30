package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Digest is optional (but recommended for verification).
func TestNewVersionCheck(t *testing.T) {
	t.Parallel()

	imageWithVersion, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "timberio/vector",
		Version: "0.50.0-distroless-static",
	})
	if err != nil {
		t.Fatalf("Failed to create test image with version: %v", err)
	}

	imageWithVersionAndDigest, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "timberio/vector",
		Version: "0.50.0-distroless-static",
		Digest:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("Failed to create test image with version and digest: %v", err)
	}

	imageWithoutVersion, err := sdk.NewImage(&sdk.ImageOpts{
		Name: "timberio/vector",
	})
	if err != nil {
		t.Fatalf("Failed to create test image without version: %v", err)
	}

	imageWithLatest, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "timberio/vector",
		Version: "latest",
	})
	if err != nil {
		t.Fatalf("Failed to create test image with latest: %v", err)
	}

	tests := []struct {
		name    string
		opName  string
		source  *sdk.Image
		force   bool
		wantErr error
	}{
		{
			name:    "valid version check with version only",
			opName:  "test-version",
			source:  imageWithVersion,
			force:   false,
			wantErr: nil,
		},
		{
			name:    "valid version check with version and digest",
			opName:  "test-version-digest",
			source:  imageWithVersionAndDigest,
			force:   false,
			wantErr: nil,
		},
		{
			name:    "valid version check with force",
			opName:  "test-version-force",
			source:  imageWithVersion,
			force:   true,
			wantErr: nil,
		},
		{
			name:    "missing source image",
			opName:  "test-version-no-source",
			source:  nil,
			force:   false,
			wantErr: sdk.ErrVersionCheckImageRequired,
		},
		{
			name:    "source image without version",
			opName:  "test-version-no-version",
			source:  imageWithoutVersion,
			force:   false,
			wantErr: sdk.ErrVersionCheckVersionRequired,
		},
		{
			name:    "source image with latest tag",
			opName:  "test-version-latest",
			source:  imageWithLatest,
			force:   false,
			wantErr: sdk.ErrVersionCheckLatestNotSupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")
			check, err := plan.CheckVersion(tt.opName, tt.source, tt.force)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("CheckVersion() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("CheckVersion() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("CheckVersion() unexpected error = %v", err)

				return
			}

			if check == nil {
				t.Error("CheckVersion() returned nil check with nil error")
			}
		})
	}
}

// INTENTION: Result accessors should return nil before execution.
func TestVersionCheck_ResultBeforeExecution(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan("test-plan")

	imageWithVersion, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "timberio/vector",
		Version: "0.50.0-distroless-static",
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	handle, err := plan.CheckVersion("test-version", imageWithVersion, false)
	if err != nil {
		t.Fatalf("CheckVersion() error = %v", err)
	}

	// Before execution, result accessor should return nil
	if handle.VersionCheckResult() != nil {
		t.Error("VersionCheckResult() before execution should return nil")
	}
}

// INTENTION: Credentials should be looked up from plan's registry collection by domain.
func TestVersionCheck_RegistryLookup(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan("test-plan")

	// Add registry credentials to plan
	plan.AddRegistry(sdk.NewRegistry(&sdk.RegistryOpts{
		Domain:   "ghcr.io",
		Username: "testuser",
		Token:    "testpass",
	}))

	// Image uses ghcr.io - should find registry credentials
	imageWithVersion, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "my-org/my-app",
		Domain:  "ghcr.io",
		Version: "1.0.0",
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	// Build should succeed and automatically lookup ghcr.io credentials
	check, err := plan.CheckVersion("test-version", imageWithVersion, false)
	if err != nil {
		t.Errorf("CheckVersion() error = %v, want nil", err)
	}

	if check == nil {
		t.Error("CheckVersion() returned nil check")
	}
}
