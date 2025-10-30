package sync_test

import (
	"testing"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/registry"
	"github.com/farcloser/quark/internal/sync"
)

// INTENTION: NewSyncer should create a valid syncer with provided clients.
func TestNewSyncer(t *testing.T) {
	t.Parallel()

	srcClient := registry.NewClient("docker.io", "", "", zerolog.Nop())
	dstClient := registry.NewClient("ghcr.io", "", "", zerolog.Nop())

	syncer := sync.NewSyncer(srcClient, dstClient, zerolog.Nop())

	if syncer == nil {
		t.Fatal("NewSyncer() returned nil, want non-nil syncer")
	}
}

// INTENTION: NewSyncer should handle nil clients gracefully (will fail at sync time).
func TestNewSyncer_NilClients(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		srcClient *registry.Client
		dstClient *registry.Client
	}{
		{
			name:      "both clients nil",
			srcClient: nil,
			dstClient: nil,
		},
		{
			name:      "source client nil",
			srcClient: nil,
			dstClient: registry.NewClient("ghcr.io", "", "", zerolog.Nop()),
		},
		{
			name:      "destination client nil",
			srcClient: registry.NewClient("docker.io", "", "", zerolog.Nop()),
			dstClient: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			syncer := sync.NewSyncer(tt.srcClient, tt.dstClient, zerolog.Nop())

			if syncer == nil {
				t.Fatal("NewSyncer() returned nil, want non-nil syncer (even with nil clients)")
			}
		})
	}
}

// INTENTION: SyncImage with empty references should fail.
// Note: This test documents that empty references are not validated at sync construction.
// Validation happens when registry client operations are invoked.
func TestSyncer_SyncImage_EmptyReferences(t *testing.T) {
	t.Parallel()

	srcClient := registry.NewClient("docker.io", "", "", zerolog.Nop())
	dstClient := registry.NewClient("ghcr.io", "", "", zerolog.Nop())
	syncer := sync.NewSyncer(srcClient, dstClient, zerolog.Nop())

	tests := []struct {
		name     string
		srcImage string
		dstImage string
	}{
		{
			name:     "both images empty",
			srcImage: "",
			dstImage: "",
		},
		{
			name:     "source image empty",
			srcImage: "",
			dstImage: "ghcr.io/test/image:latest",
		},
		{
			name:     "destination image empty",
			srcImage: "docker.io/library/alpine:latest",
			dstImage: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			digest, err := syncer.SyncImage(t.Context(), tt.srcImage, tt.dstImage)

			// Empty references should fail (either at parse or registry access)
			if err == nil {
				t.Errorf("SyncImage() error = nil, want error for empty reference")
			}

			if digest != "" {
				t.Errorf("SyncImage() digest = %q, want empty string on error", digest)
			}
		})
	}
}

// INTENTION: CheckExists with empty reference should fail.
func TestSyncer_CheckExists_EmptyReference(t *testing.T) {
	t.Parallel()

	srcClient := registry.NewClient("docker.io", "", "", zerolog.Nop())
	dstClient := registry.NewClient("ghcr.io", "", "", zerolog.Nop())
	syncer := sync.NewSyncer(srcClient, dstClient, zerolog.Nop())

	exists, err := syncer.CheckExists(t.Context(), "")

	// Empty reference should fail
	if err == nil {
		t.Error("CheckExists() error = nil, want error for empty reference")
	}

	if exists {
		t.Error("CheckExists() exists = true, want false on error")
	}
}

// INTENTION: CheckExists with invalid reference should fail at parse stage.
func TestSyncer_CheckExists_InvalidReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		imageRef string
	}{
		{
			name:     "invalid characters",
			imageRef: "invalid@@@reference",
		},
		{
			name:     "malformed digest",
			imageRef: "alpine@notadigest",
		},
		{
			name:     "malformed registry domain",
			imageRef: ":::invalid/repo:tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srcClient := registry.NewClient("docker.io", "", "", zerolog.Nop())
			dstClient := registry.NewClient("ghcr.io", "", "", zerolog.Nop())
			syncer := sync.NewSyncer(srcClient, dstClient, zerolog.Nop())

			exists, err := syncer.CheckExists(t.Context(), tt.imageRef)

			if err == nil {
				t.Error("CheckExists() error = nil, want error for invalid reference")
			}

			if exists {
				t.Error("CheckExists() exists = true, want false on error")
			}
		})
	}
}
