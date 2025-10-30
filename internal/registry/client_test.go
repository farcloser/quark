//nolint:revive,varnamelen
package registry_test

import (
	"errors"
	"testing"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/registry"
)

// INTENTION: Invalid image references should return ErrParseImageReference.
func TestClient_GetImage_InvalidReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		wantErr error
	}{
		{
			name:    "empty reference",
			ref:     "",
			wantErr: registry.ErrParseImageReference,
		},
		{
			name:    "invalid characters",
			ref:     "invalid@@@reference",
			wantErr: registry.ErrParseImageReference,
		},
		{
			name:    "malformed digest",
			ref:     "alpine@notadigest",
			wantErr: registry.ErrParseImageReference,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := registry.NewClient("docker.io", "", "", zerolog.Nop())
			_, err := client.GetImage(tt.ref)

			if err == nil {
				t.Fatal("GetImage() error = nil, want error")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("GetImage() error = %v, want error wrapping %v", err, tt.wantErr)
			}
		})
	}
}

// INTENTION: Invalid image references should return ErrParseImageReference.
func TestClient_GetDigest_InvalidReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		wantErr error
	}{
		{
			name:    "empty reference",
			ref:     "",
			wantErr: registry.ErrParseImageReference,
		},
		{
			name:    "invalid characters",
			ref:     "invalid@@@reference",
			wantErr: registry.ErrParseImageReference,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := registry.NewClient("docker.io", "", "", zerolog.Nop())
			_, err := client.GetDigest(tt.ref)

			if err == nil {
				t.Fatal("GetDigest() error = nil, want error")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("GetDigest() error = %v, want error wrapping %v", err, tt.wantErr)
			}
		})
	}
}

// INTENTION: Invalid source references should return ErrParseSourceReference.
func TestClient_CopyImage_InvalidSourceReference(t *testing.T) {
	t.Parallel()

	client := registry.NewClient("docker.io", "", "", zerolog.Nop())
	dstClient := registry.NewClient("ghcr.io", "", "", zerolog.Nop())

	_, err := client.CopyImage("invalid@@@reference", "ghcr.io/valid/image:latest", dstClient)

	if err == nil {
		t.Fatal("CopyImage() error = nil, want error")
	}

	if !errors.Is(err, registry.ErrParseSourceReference) {
		t.Errorf("CopyImage() error = %v, want error wrapping %v", err, registry.ErrParseSourceReference)
	}
}

// INTENTION: Invalid destination references should return ErrParseDestinationReference.
func TestClient_CopyImage_InvalidDestinationReference(t *testing.T) {
	t.Parallel()

	client := registry.NewClient("docker.io", "", "", zerolog.Nop())
	dstClient := registry.NewClient("ghcr.io", "", "", zerolog.Nop())

	_, err := client.CopyImage("docker.io/library/alpine:latest", "invalid@@@reference", dstClient)

	if err == nil {
		t.Fatal("CopyImage() error = nil, want error")
	}

	if !errors.Is(err, registry.ErrParseDestinationReference) {
		t.Errorf("CopyImage() error = %v, want error wrapping %v", err, registry.ErrParseDestinationReference)
	}
}

// INTENTION: Invalid source references should return ErrParseSourceReference.
func TestClient_CopyIndex_InvalidSourceReference(t *testing.T) {
	t.Parallel()

	client := registry.NewClient("docker.io", "", "", zerolog.Nop())
	dstClient := registry.NewClient("ghcr.io", "", "", zerolog.Nop())

	err := client.CopyIndex("invalid@@@reference", "ghcr.io/valid/image:latest", dstClient)

	if err == nil {
		t.Fatal("CopyIndex() error = nil, want error")
	}

	if !errors.Is(err, registry.ErrParseSourceReference) {
		t.Errorf("CopyIndex() error = %v, want error wrapping %v", err, registry.ErrParseSourceReference)
	}
}

// INTENTION: Invalid destination references should return ErrParseDestinationReference.
func TestClient_CopyIndex_InvalidDestinationReference(t *testing.T) {
	t.Parallel()

	client := registry.NewClient("docker.io", "", "", zerolog.Nop())
	dstClient := registry.NewClient("ghcr.io", "", "", zerolog.Nop())

	err := client.CopyIndex("docker.io/library/alpine:latest", "invalid@@@reference", dstClient)

	if err == nil {
		t.Fatal("CopyIndex() error = nil, want error")
	}

	if !errors.Is(err, registry.ErrParseDestinationReference) {
		t.Errorf("CopyIndex() error = %v, want error wrapping %v", err, registry.ErrParseDestinationReference)
	}
}

// INTENTION: Invalid image references should return ErrParseImageReference.
func TestClient_GetPlatformDigests_InvalidReference(t *testing.T) {
	t.Parallel()

	client := registry.NewClient("docker.io", "", "", zerolog.Nop())

	_, err := client.GetPlatformDigests("invalid@@@reference")

	if err == nil {
		t.Fatal("GetPlatformDigests() error = nil, want error")
	}

	if !errors.Is(err, registry.ErrParseImageReference) {
		t.Errorf("GetPlatformDigests() error = %v, want error wrapping %v", err, registry.ErrParseImageReference)
	}
}

// INTENTION: Invalid source references should return ErrParseSourceReference.
func TestClient_FetchPlatformImage_InvalidSourceReference(t *testing.T) {
	t.Parallel()

	client := registry.NewClient("docker.io", "", "", zerolog.Nop())

	_, err := client.FetchPlatformImage(
		"invalid@@@reference",
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	)

	if err == nil {
		t.Fatal("FetchPlatformImage() error = nil, want error")
	}

	if !errors.Is(err, registry.ErrParseSourceReference) {
		t.Errorf("FetchPlatformImage() error = %v, want error wrapping %v", err, registry.ErrParseSourceReference)
	}
}

// INTENTION: Invalid manifest references should return ErrParseManifestReference.
func TestClient_PushManifestList_InvalidReference(t *testing.T) {
	t.Parallel()

	client := registry.NewClient("docker.io", "", "", zerolog.Nop())

	_, err := client.PushManifestList("invalid@@@reference", nil)

	if err == nil {
		t.Fatal("PushManifestList() error = nil, want error")
	}

	if !errors.Is(err, registry.ErrParseManifestReference) {
		t.Errorf("PushManifestList() error = %v, want error wrapping %v", err, registry.ErrParseManifestReference)
	}
}

// INTENTION: Invalid image references should return ErrParseImageReference.
func TestClient_CheckExists_InvalidReference(t *testing.T) {
	t.Parallel()

	client := registry.NewClient("docker.io", "", "", zerolog.Nop())

	_, err := client.CheckExists("invalid@@@reference")

	if err == nil {
		t.Fatal("CheckExists() error = nil, want error")
	}

	if !errors.Is(err, registry.ErrParseImageReference) {
		t.Errorf("CheckExists() error = %v, want error wrapping %v", err, registry.ErrParseImageReference)
	}
}

// INTENTION: Invalid image references should return ErrParseImageReference.
func TestClient_GetImageHandle_InvalidReference(t *testing.T) {
	t.Parallel()

	client := registry.NewClient("docker.io", "", "", zerolog.Nop())

	_, err := client.GetImageHandle("invalid@@@reference")

	if err == nil {
		t.Fatal("GetImageHandle() error = nil, want error")
	}

	if !errors.Is(err, registry.ErrParseImageReference) {
		t.Errorf("GetImageHandle() error = %v, want error wrapping %v", err, registry.ErrParseImageReference)
	}
}
