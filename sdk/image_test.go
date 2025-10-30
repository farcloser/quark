//nolint:revive,varnamelen,wsl
package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Digest is optional but must be valid format if provided.
func TestImageBuilder_Build(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		build   func() (*sdk.Image, error)
		wantErr error
	}{
		{
			name: "valid image with just name",
			build: func() (*sdk.Image, error) {
				return sdk.NewImage("alpine").Build()
			},
			wantErr: nil,
		},
		{
			name: "valid image with domain",
			build: func() (*sdk.Image, error) {
				return sdk.NewImage("alpine").Domain("docker.io").Build()
			},
			wantErr: nil,
		},
		{
			name: "valid image with version",
			build: func() (*sdk.Image, error) {
				return sdk.NewImage("alpine").Version("3.20").Build()
			},
			wantErr: nil,
		},
		{
			name: "valid image with digest",
			build: func() (*sdk.Image, error) {
				return sdk.NewImage("alpine").
					Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid image with all fields",
			build: func() (*sdk.Image, error) {
				return sdk.NewImage("my-org/my-app").
					Domain("ghcr.io").
					Version("v1.2.3").
					Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").
					Build()
			},
			wantErr: nil,
		},
		{
			name: "empty name should fail",
			build: func() (*sdk.Image, error) {
				return sdk.NewImage("").Build()
			},
			wantErr: sdk.ErrImageNameRequired,
		},
		{
			name: "whitespace-only name should fail",
			build: func() (*sdk.Image, error) {
				return sdk.NewImage("   ").Build()
			},
			wantErr: sdk.ErrImageNameRequired,
		},
		{
			name: "digest without sha256 prefix should fail",
			build: func() (*sdk.Image, error) {
				return sdk.NewImage("alpine").
					Digest("0123456789abcdef").
					Build()
			},
			wantErr: sdk.ErrInvalidImageDigest,
		},
		{
			name: "digest with invalid characters should fail",
			build: func() (*sdk.Image, error) {
				return sdk.NewImage("alpine").
					Digest("sha256:ZZZZZZZZZZ").
					Build()
			},
			wantErr: sdk.ErrInvalidImageDigest,
		},
		{
			name: "digest too short should fail",
			build: func() (*sdk.Image, error) {
				return sdk.NewImage("alpine").
					Digest("sha256:abc").
					Build()
			},
			wantErr: sdk.ErrInvalidImageDigest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			img, err := tt.build()

			// Verify error matches expectation
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

			// No error expected - verify image is usable
			if err != nil {
				t.Errorf("Build() unexpected error = %v", err)

				return
			}

			if img == nil {
				t.Error("Build() returned nil image with nil error")
			}
		})
	}
}

// INTENTION: Once built, image properties cannot change.
func TestImageBuilder_Immutability(t *testing.T) {
	t.Parallel()

	img, err := sdk.NewImage("alpine").Version("3.20").Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Verify getters return correct values
	if img.Name() != "alpine" {
		t.Errorf("Name() = %q, want %q", img.Name(), "alpine")
	}

	if img.Version() != "3.20" {
		t.Errorf("Version() = %q, want %q", img.Version(), "3.20")
	}
	// Image should have no setters - immutability enforced at compile time
	// This test documents the design intention
}

// INTENTION: Empty domain should normalize to docker.io.
func TestImageBuilder_DomainNormalization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		domain     string
		wantDomain string
	}{
		{
			name:       "empty domain defaults to docker.io",
			domain:     "",
			wantDomain: "docker.io",
		},
		{
			name:       "explicit docker.io preserved",
			domain:     "docker.io",
			wantDomain: "docker.io",
		},
		{
			name:       "custom domain preserved",
			domain:     "ghcr.io",
			wantDomain: "ghcr.io",
		},
		{
			name:       "localhost preserved",
			domain:     "localhost:5000",
			wantDomain: "localhost:5000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			builder := sdk.NewImage("alpine")
			if tt.domain != "" {
				builder = builder.Domain(tt.domain)
			}

			img, err := builder.Build()
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}

			if img.Domain() != tt.wantDomain {
				t.Errorf("Domain() = %q, want %q", img.Domain(), tt.wantDomain)
			}
		})
	}
}

// INTENTION: Names should be validated for container registry compatibility.
func TestImageBuilder_NameValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		imgName string
		wantErr bool
	}{
		{
			name:    "simple name",
			imgName: "alpine",
			wantErr: false,
		},
		{
			name:    "namespaced name",
			imgName: "library/alpine",
			wantErr: false,
		},
		{
			name:    "deeply namespaced name",
			imgName: "my-org/team/app",
			wantErr: false,
		},
		{
			name:    "name with hyphens",
			imgName: "my-app",
			wantErr: false,
		},
		{
			name:    "name with underscores",
			imgName: "my_app",
			wantErr: false,
		},
		{
			name:    "empty name fails",
			imgName: "",
			wantErr: true,
		},
		{
			name:    "whitespace name fails",
			imgName: "  ",
			wantErr: true,
		},
		{
			name:    "name with only slashes fails",
			imgName: "//",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := sdk.NewImage(tt.imgName).Build()

			if tt.wantErr && err == nil {
				t.Error("Build() error = nil, want error")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Build() error = %v, want nil", err)
			}
		})
	}
}

// INTENTION: Digests must be valid sha256 format if provided.
func TestImageBuilder_DigestValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		digest  string
		wantErr error
	}{
		{
			name:    "valid sha256 digest",
			digest:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: nil,
		},
		{
			name:    "digest without sha256 prefix",
			digest:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: sdk.ErrInvalidImageDigest,
		},
		{
			name:    "digest with wrong prefix",
			digest:  "sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: sdk.ErrInvalidImageDigest,
		},
		{
			name:    "digest too short",
			digest:  "sha256:abc123",
			wantErr: sdk.ErrInvalidImageDigest,
		},
		{
			name:    "digest with invalid characters",
			digest:  "sha256:GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
			wantErr: sdk.ErrInvalidImageDigest,
		},
		{
			name:    "empty digest (optional)",
			digest:  "",
			wantErr: nil,
		},
		{
			name:    "whitespace digest",
			digest:  "  ",
			wantErr: sdk.ErrInvalidImageDigest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := sdk.NewImage("alpine").Digest(tt.digest).Build()

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
				t.Errorf("Build() error = %v, want nil", err)
			}
		})
	}
}
