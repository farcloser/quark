//nolint:revive,varnamelen,wsl
package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Platforms are optional (default to AMD64+ARM64).
func TestSyncBuilder_Build(t *testing.T) {
	t.Parallel()

	// Create test images
	sourceWithDigest, err := sdk.NewImage("alpine").
		Version("3.20").
		Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	sourceWithoutDigest, err := sdk.NewImage("alpine").
		Version("3.20").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	destImage, err := sdk.NewImage("my-org/alpine").
		Domain("ghcr.io").
		Version("3.20").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test destination image: %v", err)
	}

	tests := []struct {
		name    string
		build   func(*sdk.Plan) (*sdk.Sync, error)
		wantErr error
	}{
		{
			name: "valid sync with digest",
			build: func(plan *sdk.Plan) (*sdk.Sync, error) {
				return plan.Sync("test-sync").
					Source(sourceWithDigest).
					Destination(destImage).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid sync with explicit platforms",
			build: func(plan *sdk.Plan) (*sdk.Sync, error) {
				return plan.Sync("test-sync-platforms").
					Source(sourceWithDigest).
					Destination(destImage).
					Platforms(sdk.PlatformAMD64).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "missing source image",
			build: func(plan *sdk.Plan) (*sdk.Sync, error) {
				return plan.Sync("test-sync-no-source").
					Destination(destImage).
					Build()
			},
			wantErr: sdk.ErrSyncSourceRequired,
		},
		{
			name: "missing destination image",
			build: func(plan *sdk.Plan) (*sdk.Sync, error) {
				return plan.Sync("test-sync-no-dest").
					Source(sourceWithDigest).
					Build()
			},
			wantErr: sdk.ErrSyncDestinationRequired,
		},
		{
			name: "source image without digest (security violation)",
			build: func(plan *sdk.Plan) (*sdk.Sync, error) {
				return plan.Sync("test-sync-no-digest").
					Source(sourceWithoutDigest).
					Destination(destImage).
					Build()
			},
			wantErr: sdk.ErrSyncSourceDigestRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")
			sync, err := tt.build(plan)

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

			if sync == nil {
				t.Error("Build() returned nil sync with nil error")
			}
		})
	}
}

// INTENTION: If no platforms specified, should default to both AMD64 and ARM64.
func TestSyncBuilder_DefaultPlatforms(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan("test-plan")

	sourceWithDigest, err := sdk.NewImage("alpine").
		Version("3.20").
		Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	destImage, err := sdk.NewImage("my-org/alpine").
		Domain("ghcr.io").
		Version("3.20").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test destination image: %v", err)
	}

	// Build without explicit platforms
	_, err = plan.Sync("test-sync").
		Source(sourceWithDigest).
		Destination(destImage).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}
	// Note: Cannot inspect platforms directly (unexported field)
	// This test documents the intention - platforms default to AMD64+ARM64
}

// INTENTION: Credentials should be looked up from plan's registry collection by domain.
func TestSyncBuilder_RegistryLookup(t *testing.T) {
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

	sourceWithDigest, err := sdk.NewImage("alpine").
		Domain("docker.io").
		Version("3.20").
		Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	// Destination uses ghcr.io - should find registry credentials
	destImage, err := sdk.NewImage("my-org/alpine").
		Domain("ghcr.io").
		Version("3.20").
		Build()
	if err != nil {
		t.Fatalf("Failed to create test destination image: %v", err)
	}

	// Build should succeed and automatically lookup ghcr.io credentials
	sync, err := plan.Sync("test-sync").
		Source(sourceWithDigest).
		Destination(destImage).
		Build()
	if err != nil {
		t.Errorf("Build() error = %v, want nil", err)
	}

	if sync == nil {
		t.Error("Build() returned nil sync")
	}
	// Note: Cannot verify credentials were found (unexported fields)
	// This test documents the intention - credentials should be looked up
}
