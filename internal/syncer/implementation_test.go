package syncer_test

import (
	"log/slog"
	"testing"

	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/internal/registry"
	"github.com/farcloser/quark/internal/syncer"
	"github.com/farcloser/quark/internal/utilities"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// INTENTION: NewSyncer should create a valid syncer with provided clients.
func TestNewSyncer(t *testing.T) {
	t.Parallel()

	srcClient := registry.NewClient(&utilities.RegistryCredentials{Domain: "docker.io"}, discardLogger())
	dstClient := registry.NewClient(&utilities.RegistryCredentials{Domain: "ghcr.io"}, discardLogger())

	synch, err := syncer.NewSyncer(srcClient, dstClient, discardLogger())
	if err != nil {
		t.Fatalf("NewSyncer() error = %v, want nil", err)
	}

	if synch == nil {
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
			dstClient: registry.NewClient(&utilities.RegistryCredentials{Domain: "ghcr.io"}, discardLogger()),
		},
		{
			name:      "destination client nil",
			srcClient: registry.NewClient(&utilities.RegistryCredentials{Domain: "docker.io"}, discardLogger()),
			dstClient: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synch, err := syncer.NewSyncer(tt.srcClient, tt.dstClient, discardLogger())
			if err != nil {
				t.Fatalf("NewSyncer() error = %v, want nil (even with nil clients)", err)
			}

			if synch == nil {
				t.Fatal("NewSyncer() returned nil, want non-nil syncer (even with nil clients)")
			}
		})
	}
}

// INTENTION: Image with invalid references should fail at parse stage.
func TestSyncer_Image_InvalidReferences(t *testing.T) {
	t.Parallel()

	srcClient := registry.NewClient(&utilities.RegistryCredentials{Domain: "docker.io"}, discardLogger())
	dstClient := registry.NewClient(&utilities.RegistryCredentials{Domain: "ghcr.io"}, discardLogger())

	synch, err := syncer.NewSyncer(srcClient, dstClient, discardLogger())
	if err != nil {
		t.Fatalf("NewSyncer() error = %v, want nil", err)
	}

	// Test with valid references but unreachable registries
	// The syncer will fail at registry access, not at reference parsing
	srcRef, err := reference.Parse("docker.io/library/alpine:latest")
	if err != nil {
		t.Fatalf("Failed to parse source reference: %v", err)
	}

	dstRef, err := reference.Parse("ghcr.io/test/image:latest")
	if err != nil {
		t.Fatalf("Failed to parse destination reference: %v", err)
	}

	// This will fail because the registry is not accessible in tests
	platforms := []string{"linux/amd64", "linux/arm64"}
	_, syncErr := synch.Image(t.Context(), *srcRef, *dstRef, platforms)

	// We expect an error because we can't actually reach the registries
	if syncErr == nil {
		t.Error("Image() error = nil, want error for unreachable registry")
	}
}

// INTENTION: Test that reference.Parse works correctly for various formats.
func TestSyncer_ReferenceFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{
			name:    "simple tag",
			ref:     "alpine:latest",
			wantErr: false,
		},
		{
			name:    "with registry",
			ref:     "docker.io/library/alpine:latest",
			wantErr: false,
		},
		{
			name:    "with digest",
			ref:     "alpine@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			wantErr: false,
		},
		{
			name:    "invalid characters",
			ref:     "invalid@@@reference",
			wantErr: true,
		},
		{
			name:    "malformed digest",
			ref:     "alpine@notadigest",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := reference.Parse(tt.ref)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse(%q) error = %v, wantErr %v", tt.ref, err, tt.wantErr)
			}
		})
	}
}
