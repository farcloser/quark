package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Platforms are optional (default to AMD64+ARM64).
func TestNewSync(t *testing.T) {
	t.Parallel()

	// Create test images
	sourceWithDigest, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "alpine",
		Version: "3.20",
		Digest:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	sourceWithTagOnly, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "alpine",
		Version: "3.20",
	})
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	sourceWithNoTagNoDigest, err := sdk.NewImage(&sdk.ImageOpts{
		Name: "alpine",
	})
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	destImage, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "my-org/alpine",
		Domain:  "ghcr.io",
		Version: "3.20",
	})
	if err != nil {
		t.Fatalf("Failed to create test destination image: %v", err)
	}

	tests := []struct {
		name    string
		args    *sdk.SyncArgs
		wantErr error
	}{
		{
			name: "valid sync with digest",
			args: &sdk.SyncArgs{
				Description: "test-sync",
				Source:      sourceWithDigest,
				Destination: destImage,
			},
			wantErr: nil,
		},
		{
			name: "valid sync with explicit platforms",
			args: &sdk.SyncArgs{
				Description: "test-sync-platforms",
				Source:      sourceWithDigest,
				Destination: destImage,
				Platforms:   []sdk.Platform{sdk.PlatformAMD64},
			},
			wantErr: nil,
		},
		{
			name: "missing source image",
			args: &sdk.SyncArgs{
				Description: "test-sync-no-source",
				Destination: destImage,
			},
			wantErr: sdk.ErrSyncSourceRequired,
		},
		{
			name: "missing destination image",
			args: &sdk.SyncArgs{
				Description: "test-sync-no-dest",
				Source:      sourceWithDigest,
			},
			wantErr: sdk.ErrSyncDestinationRequired,
		},
		{
			name: "valid sync with tag only (signature verified at runtime)",
			args: &sdk.SyncArgs{
				Description: "test-sync-tag-only",
				Source:      sourceWithTagOnly,
				Destination: destImage,
			},
			wantErr: nil,
		},
		{
			name: "source image without tag or digest",
			args: &sdk.SyncArgs{
				Description: "test-sync-no-tag-no-digest",
				Source:      sourceWithNoTagNoDigest,
				Destination: destImage,
			},
			wantErr: sdk.ErrMustSpecifyTagOrDigest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")
			sync, err := plan.Sync(tt.args)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Sync() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Sync() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("Sync() unexpected error = %v", err)

				return
			}

			if sync == nil {
				t.Error("Sync() returned nil sync with nil error")
			}
		})
	}
}

// INTENTION: If no platforms specified, should default to both AMD64 and ARM64.
func TestSync_DefaultPlatforms(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan("test-plan")

	sourceWithDigest, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "alpine",
		Version: "3.20",
		Digest:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	destImage, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "my-org/alpine",
		Domain:  "ghcr.io",
		Version: "3.20",
	})
	if err != nil {
		t.Fatalf("Failed to create test destination image: %v", err)
	}

	// Build without explicit platforms
	_, err = plan.Sync(&sdk.SyncArgs{
		Description: "test-sync",
		Source:      sourceWithDigest,
		Destination: destImage,
	})
	if err != nil {
		t.Fatalf("Sync() error = %v, want nil", err)
	}
}

// INTENTION: Credentials should be looked up from plan's registry collection by domain.
func TestSync_RegistryLookup(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan("test-plan")

	// Add registry credentials to plan
	plan.AddRegistry(sdk.NewRegistry(&sdk.RegistryOpts{
		Domain:   "ghcr.io",
		Username: "testuser",
		Token:    "testpass",
	}))

	sourceWithDigest, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "alpine",
		Domain:  "docker.io",
		Version: "3.20",
		Digest:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("Failed to create test source image: %v", err)
	}

	// Destination uses ghcr.io - should find registry credentials
	destImage, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "my-org/alpine",
		Domain:  "ghcr.io",
		Version: "3.20",
	})
	if err != nil {
		t.Fatalf("Failed to create test destination image: %v", err)
	}

	// Build should succeed and automatically lookup ghcr.io credentials
	sync, err := plan.Sync(&sdk.SyncArgs{
		Description: "test-sync",
		Source:      sourceWithDigest,
		Destination: destImage,
	})
	if err != nil {
		t.Errorf("Sync() error = %v, want nil", err)
	}

	// Note: Cannot verify credentials were found (unexported fields)
	// This test documents the intention - credentials should be looked up
	if sync == nil {
		t.Error("Sync() returned nil sync")
	}
}
