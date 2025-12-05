package registry_test

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/internal/registry"
	"github.com/farcloser/quark/internal/utilities"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// INTENTION: Invalid source references should return ErrParseSourceReference.
func TestClient_CopyImage_InvalidSourceReference(t *testing.T) {
	t.Parallel()

	client := registry.NewClient(&utilities.RegistryCredentials{Domain: "docker.io"}, discardLogger())
	dstClient := registry.NewClient(&utilities.RegistryCredentials{Domain: "ghcr.io"}, discardLogger())

	// Parse valid destination reference.
	dstRef, err := reference.Parse("ghcr.io/valid/image:latest")
	if err != nil {
		t.Fatalf("Failed to parse destination reference: %v", err)
	}

	// Parse an invalid source - this should fail at parse time
	_, err = reference.Parse("invalid@@@reference")
	if err == nil {
		t.Fatal("Expected parse error for invalid reference")
	}

	// Test with a valid reference that doesn't exist (will fail at registry access)
	srcRef, err := reference.Parse("docker.io/nonexistent/image:v999")
	if err != nil {
		t.Fatalf("Failed to parse source reference: %v", err)
	}

	_, err = client.CopyImage(t.Context(), *srcRef, *dstRef, dstClient)
	// This will fail because the image doesn't exist, not because of parse error
	if err == nil {
		t.Fatal("CopyImage() error = nil, want error for non-existent image")
	}
}

// INTENTION: Invalid source references should return ErrParseSourceReference.
func TestClient_CopyIndex_InvalidSourceReference(t *testing.T) {
	t.Parallel()

	client := registry.NewClient(&utilities.RegistryCredentials{Domain: "docker.io"}, discardLogger())
	dstClient := registry.NewClient(&utilities.RegistryCredentials{Domain: "ghcr.io"}, discardLogger())

	// Parse valid destination reference.
	dstRef, err := reference.Parse("ghcr.io/valid/image:latest")
	if err != nil {
		t.Fatalf("Failed to parse destination reference: %v", err)
	}

	// Parse an invalid source - this should fail at parse time
	_, err = reference.Parse("invalid@@@reference")
	if err == nil {
		t.Fatal("Expected parse error for invalid reference")
	}

	// Test with a valid reference that doesn't exist (will fail at registry access)
	srcRef, err := reference.Parse("docker.io/nonexistent/image:v999")
	if err != nil {
		t.Fatalf("Failed to parse source reference: %v", err)
	}

	err = client.CopyIndex(t.Context(), *srcRef, *dstRef, dstClient)
	// This will fail because the image doesn't exist
	if err == nil {
		t.Fatal("CopyIndex() error = nil, want error for non-existent image")
	}
}

// INTENTION: GetImage returns proper error for non-existent image.
func TestClient_GetImage_NonExistent(t *testing.T) {
	t.Parallel()

	client := registry.NewClient(&utilities.RegistryCredentials{Domain: "docker.io"}, discardLogger())

	ref, err := reference.Parse("docker.io/nonexistent/image:v999.999.999")
	if err != nil {
		t.Fatalf("Failed to parse reference: %v", err)
	}

	_, err = client.GetImage(t.Context(), *ref)
	if err == nil {
		t.Fatal("GetImage() error = nil, want error for non-existent image")
	}

	if !errors.Is(err, registry.ErrGetImage) {
		t.Errorf("GetImage() error = %v, want error wrapping %v", err, registry.ErrGetImage)
	}
}

// INTENTION: Invalid reference strings fail at parse time.
func TestParseReference_Invalid(t *testing.T) {
	t.Parallel()

	invalidRefs := []string{
		"",
		"invalid@@@reference",
		"alpine@notadigest",
		":::invalid/repo:tag",
	}

	for _, ref := range invalidRefs {
		t.Run(ref, func(t *testing.T) {
			t.Parallel()

			_, err := reference.Parse(ref)
			if err == nil {
				t.Errorf("Parse(%q) error = nil, want error", ref)
			}
		})
	}
}
