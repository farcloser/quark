package syft

import (
	"context"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/farcloser/quark/internal/types"
)

// Generator provides SBOM generation for container images.
type Generator interface {
	// GenerateSBOM generates CycloneDX SBOMs for the specified OCI tarball and platforms.
	// The tarballPath should be a path to an OCI tarball (e.g., from buildctl --output type=oci,dest=image.tar).
	// The platforms slice specifies which platforms to generate SBOMs for (e.g., [linux/amd64, linux/arm64]).
	// Returns a map of platform to CycloneDX BOM struct for programmatic use.
	GenerateSBOM(
		ctx context.Context,
		tarballPath string,
		platforms []*types.Platform,
	) (map[*types.Platform]*cdx.BOM, error)
}

// NewGenerator creates a new SBOM generator.
func NewGenerator(log *slog.Logger) Generator {
	return &generator{
		log: log.With("component", "syft"),
	}
}
