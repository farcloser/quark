package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Digest is optional but must be valid format if provided.
func TestNewImageFromArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    *sdk.ImageOpts
		wantErr error
	}{
		{
			name:    "valid image with just name",
			args:    &sdk.ImageOpts{Name: "alpine"},
			wantErr: nil,
		},
		{
			name:    "valid image with domain",
			args:    &sdk.ImageOpts{Name: "alpine", Domain: "docker.io"},
			wantErr: nil,
		},
		{
			name:    "valid image with version",
			args:    &sdk.ImageOpts{Name: "alpine", Version: "3.20"},
			wantErr: nil,
		},
		{
			name: "valid image with digest",
			args: &sdk.ImageOpts{
				Name:   "alpine",
				Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: nil,
		},
		{
			name: "valid image with all fields",
			args: &sdk.ImageOpts{
				Name:    "my-org/my-app",
				Domain:  "ghcr.io",
				Version: "v1.2.3",
				Digest:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			wantErr: nil,
		},
		{
			name:    "empty name should fail",
			args:    &sdk.ImageOpts{Name: ""},
			wantErr: sdk.ErrImageNameRequired,
		},
		{
			name:    "whitespace-only name should fail",
			args:    &sdk.ImageOpts{Name: "   "},
			wantErr: sdk.ErrImageNameRequired,
		},
		{
			name:    "digest without sha256 prefix should fail",
			args:    &sdk.ImageOpts{Name: "alpine", Digest: "0123456789abcdef"},
			wantErr: sdk.ErrInvalidImageDigest,
		},
		{
			name:    "digest with invalid characters should fail",
			args:    &sdk.ImageOpts{Name: "alpine", Digest: "sha256:ZZZZZZZZZZ"},
			wantErr: sdk.ErrInvalidImageDigest,
		},
		{
			name:    "digest too short should fail",
			args:    &sdk.ImageOpts{Name: "alpine", Digest: "sha256:abc"},
			wantErr: sdk.ErrInvalidImageDigest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			img, err := sdk.NewImage(tt.args)

			// Verify error matches expectation
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("NewImageFromArgs() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("NewImageFromArgs() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			// No error expected - verify image is usable
			if err != nil {
				t.Errorf("NewImageFromArgs() unexpected error = %v", err)

				return
			}

			if img == nil {
				t.Error("NewImageFromArgs() returned nil image with nil error")
			}
		})
	}
}

// INTENTION: Once built, image properties cannot change.
func TestImage_Immutability(t *testing.T) {
	t.Parallel()

	img, err := sdk.NewImage(&sdk.ImageOpts{Name: "alpine", Version: "3.20"})
	if err != nil {
		t.Fatalf("NewImageFromArgs() error = %v", err)
	}

	// Verify getters return correct values
	if img.Name() != "alpine" {
		t.Errorf("Name() = %q, want %q", img.Name(), "alpine")
	}

	if img.Version() != "3.20" {
		t.Errorf("Version() = %q, want %q", img.Version(), "3.20")
	}
}

// INTENTION: Empty domain should normalize to docker.io.
func TestImage_DomainNormalization(t *testing.T) {
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

			img, err := sdk.NewImage(&sdk.ImageOpts{
				Name:   "alpine",
				Domain: tt.domain,
			})
			if err != nil {
				t.Fatalf("NewImageFromArgs() error = %v", err)
			}

			if img.Domain() != tt.wantDomain {
				t.Errorf("Domain() = %q, want %q", img.Domain(), tt.wantDomain)
			}
		})
	}
}

// INTENTION: Names should be validated for container registry compatibility.
func TestImage_NameValidation(t *testing.T) {
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

			_, err := sdk.NewImage(&sdk.ImageOpts{Name: tt.imgName})

			if tt.wantErr && err == nil {
				t.Error("NewImageFromArgs() error = nil, want error")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("NewImageFromArgs() error = %v, want nil", err)
			}
		})
	}
}

// INTENTION: Digests must be valid sha256 format if provided.
func TestImage_DigestValidation(t *testing.T) {
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

			_, err := sdk.NewImage(&sdk.ImageOpts{Name: "alpine", Digest: tt.digest})

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("NewImageFromArgs() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("NewImageFromArgs() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("NewImageFromArgs() error = %v, want nil", err)
			}
		})
	}
}
