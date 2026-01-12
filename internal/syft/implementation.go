package syft

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/source/stereoscopesource"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"

	"github.com/farcloser/quark/internal/types"
)

const (
	logKeyTarball  = "tarball"
	logKeyPlatform = "platform"
)

// generator implements the Generator interface using syft library.
type generator struct {
	log *slog.Logger
}

// GenerateSBOM generates CycloneDX SBOMs for the specified OCI tarball and platforms.
func (g *generator) GenerateSBOM(
	ctx context.Context,
	tarballPath string,
	platforms []*types.Platform,
) (map[*types.Platform]*cdx.BOM, error) {
	results := make(map[*types.Platform]*cdx.BOM, len(platforms))

	// Extract tarball once for all platforms
	extractDir, cleanup, err := g.extractTarball(tarballPath)
	if err != nil {
		return nil, err
	}

	defer cleanup()

	// Parse OCI layout
	ociPath, err := layout.FromPath(extractDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOCILayout, err)
	}

	// Get the image index
	idx, err := ociPath.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOCILayout, err)
	}

	idxManifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOCILayout, err)
	}

	for _, platform := range platforms {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCancelled, err)
		}

		bom, err := g.generateForPlatform(ctx, ociPath, idxManifest, platform)
		if err != nil {
			return nil, err
		}

		results[platform] = bom
	}

	return results, nil
}

// extractTarball extracts an OCI tarball to a temporary directory.
// Returns the extraction path and a cleanup function.
func (g *generator) extractTarball(tarballPath string) (string, func(), error) {
	tarFile, err := os.Open(tarballPath) //nolint:gosec // tarball path is provided by caller
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrTarballOpenFailed, err)
	}

	defer tarFile.Close()

	extractDir, err := os.MkdirTemp("", "quark-oci-*")
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrTarballExtractFailed, err)
	}

	cleanup := func() {
		if removeErr := os.RemoveAll(extractDir); removeErr != nil {
			g.log.Warn("failed to cleanup temp directory", "path", extractDir, "error", removeErr)
		}
	}

	if err := file.UntarToDirectory(tarFile, extractDir); err != nil {
		cleanup()

		return "", nil, fmt.Errorf("%w: %w", ErrTarballExtractFailed, err)
	}

	return extractDir, cleanup, nil
}

// generateForPlatform generates a CycloneDX SBOM for a single platform from an OCI layout.
func (g *generator) generateForPlatform(
	ctx context.Context,
	ociPath layout.Path,
	idxManifest *v1.IndexManifest,
	platform *types.Platform,
) (*cdx.BOM, error) {
	g.log.DebugContext(ctx, "generating SBOM for platform", logKeyPlatform, platform)

	// Find the manifest descriptor matching the platform
	descriptor, err := g.findPlatformDescriptor(idxManifest, platform)
	if err != nil {
		return nil, err
	}

	// Get the v1.Image for the specific platform
	gcrImage, err := ociPath.Image(descriptor.Digest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSourceCreationFailed, err)
	}

	// Create stereoscope image from v1.Image
	tmpDirGen := file.NewTempDirGenerator("quark-syft")

	defer func() {
		if cleanupErr := tmpDirGen.Cleanup(); cleanupErr != nil {
			g.log.Warn("failed to cleanup stereoscope temp dirs", "error", cleanupErr)
		}
	}()

	contentDir, err := tmpDirGen.NewDirectory("content")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSourceCreationFailed, err)
	}

	stereoImage := image.New(
		gcrImage,
		tmpDirGen,
		contentDir,
		image.WithManifestDigest(descriptor.Digest.String()),
		image.WithPlatform(platform.String()),
	)

	if err := stereoImage.Read(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSourceCreationFailed, err)
	}

	// Create syft source from stereoscope image
	src := stereoscopesource.New(stereoImage, stereoscopesource.ImageConfig{
		Reference: descriptor.Digest.String(),
	})

	defer src.Close()

	// Generate SBOM
	sbomConfig := syft.DefaultCreateSBOMConfig()

	sbomResult, err := syft.CreateSBOM(ctx, src, sbomConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSBOMCreationFailed, err)
	}

	// Encode to CycloneDX JSON
	encoderConfig := cyclonedxjson.DefaultEncoderConfig()

	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(encoderConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSBOMEncodingFailed, err)
	}

	var buf bytes.Buffer

	if err := encoder.Encode(&buf, *sbomResult); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSBOMEncodingFailed, err)
	}

	// Decode to CycloneDX Go struct
	bom := new(cdx.BOM)

	decoder := cdx.NewBOMDecoder(&buf, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSBOMDecodingFailed, err)
	}

	g.log.DebugContext(ctx, "SBOM generation complete", logKeyPlatform, platform)

	return bom, nil
}

// findPlatformDescriptor finds the manifest descriptor matching the specified platform.
func (*generator) findPlatformDescriptor(
	idxManifest *v1.IndexManifest,
	platform *types.Platform,
) (*v1.Descriptor, error) {
	for idx := range idxManifest.Manifests {
		desc := &idxManifest.Manifests[idx]
		if desc.Platform == nil {
			continue
		}

		// Match OS and architecture; variant is optional.
		if desc.Platform.OS == platform.OS && desc.Platform.Architecture == platform.Architecture {
			// If we specified a variant, it must match.
			if platform.Variant != "" && desc.Platform.Variant != platform.Variant {
				continue
			}

			return desc, nil
		}
	}

	return nil, fmt.Errorf("%w: %q", ErrPlatformNotFound, platform.String())
}
