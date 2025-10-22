// Package sync provides image synchronization operations.
package sync

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/registry"
)

// Syncer handles image synchronization between registries.
type Syncer struct {
	srcClient *registry.Client
	dstClient *registry.Client
	log       zerolog.Logger
}

// NewSyncer creates a new image syncer.
func NewSyncer(srcClient, dstClient *registry.Client, log zerolog.Logger) *Syncer {
	return &Syncer{
		srcClient: srcClient,
		dstClient: dstClient,
		log:       log,
	}
}

// SyncImage synchronizes an image from source to destination.
// For multi-platform images, copies each platform separately and creates manifest list.
// This matches the approach used by black/scripts/sync-images.sh.
// Returns the destination image digest (computed locally, not from registry for security).
func (syncer *Syncer) SyncImage(srcImage, dstImage string) (string, error) {
	syncer.log.Debug().
		Str("source", srcImage).
		Str("destination", dstImage).
		Msg("starting image sync")

	// Check if source exists and get descriptor
	desc, err := syncer.srcClient.GetImage(srcImage)
	if err != nil {
		return "", fmt.Errorf("failed to get source image: %w", err)
	}

	// Determine if this is an index (multi-platform) or single image
	if desc.MediaType.IsIndex() {
		syncer.log.Debug().Msg("detected multi-platform image index")

		return syncer.syncMultiPlatform(srcImage, dstImage)
	}

	syncer.log.Debug().Msg("detected single-platform image")

	return syncer.syncSinglePlatform(srcImage, dstImage)
}

// syncMultiPlatform syncs a multi-platform image by copying each platform separately.
// This is the same approach as black/scripts/sync-images.sh:
// 1. Get platform digests from source
// 2. Copy each platform image by digest
// 3. Create and push manifest list at destination
// Returns the destination manifest list digest (computed locally for security).
func (syncer *Syncer) syncMultiPlatform(srcImage, dstImage string) (string, error) {
	// Get platform-specific digests
	platformDigests, err := syncer.srcClient.GetPlatformDigests(srcImage)
	if err != nil {
		return "", fmt.Errorf("failed to get platform digests: %w", err)
	}

	syncer.log.Debug().
		Int("platforms", len(platformDigests)).
		Msg("found platforms in source image")

	// Only sync linux/amd64 and linux/arm64 platforms
	supportedPlatforms := []string{"linux/amd64", "linux/arm64"}

	// Copy each supported platform separately and collect the images
	platformImages := make(map[string]v1.Image)

	for platform, digest := range platformDigests {
		// Skip unsupported platforms
		supported := false

		for _, sp := range supportedPlatforms {
			if platform == sp {
				supported = true

				break
			}
		}

		if !supported {
			syncer.log.Debug().
				Str("platform", platform).
				Msg("skipping unsupported platform")

			continue
		}

		syncer.log.Debug().
			Str("platform", platform).
			Str("digest", digest).
			Msg("fetching platform image")

		// Fetch this platform image and get the TRUSTED source image
		// FetchPlatformImage returns the image fetched from source BY DIGEST
		// This ensures we build the manifest list from verified content, not from destination
		// Note: The image will be pushed by digest (not by tag) when PushManifestList is called
		img, err := syncer.srcClient.FetchPlatformImage(stripTag(srcImage), digest)
		if err != nil {
			return "", fmt.Errorf("failed to fetch platform %s: %w", platform, err)
		}

		// Use the TRUSTED source image (fetched by digest) for manifest list
		// SECURITY: Never fetch from destination - only use source images verified by digest
		platformImages[platform] = img
	}

	// Create and push manifest list
	syncer.log.Debug().
		Str("destination", dstImage).
		Msg("creating manifest list")

	digest, err := syncer.dstClient.PushManifestList(dstImage, platformImages)
	if err != nil {
		return "", fmt.Errorf("failed to create manifest list: %w", err)
	}

	syncer.log.Debug().
		Str("digest", digest).
		Msg("manifest list created successfully")

	return digest, nil
}

// syncSinglePlatform syncs a single-platform image.
// Returns the destination image digest (computed locally for security).
func (syncer *Syncer) syncSinglePlatform(srcImage, dstImage string) (string, error) {
	// Copy the image and get the TRUSTED source image
	// CopyImage returns the image fetched from source BY DIGEST
	// SECURITY: Never fetch from destination - only use source image verified by digest
	img, err := syncer.srcClient.CopyImage(srcImage, dstImage, syncer.dstClient)
	if err != nil {
		return "", fmt.Errorf("failed to copy image: %w", err)
	}

	// Compute digest from TRUSTED source image (not from destination)
	digest, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("failed to compute image digest: %w", err)
	}

	syncer.log.Debug().
		Str("digest", digest.String()).
		Msg("single-platform image synced successfully")

	return digest.String(), nil
}

// Handles both formats: "registry/repo:tag" and "registry/repo@digest".
func stripTag(imageRef string) string {
	// Check for digest format first (@sha256:...)
	if atIdx := strings.Index(imageRef, "@"); atIdx != -1 {
		return imageRef[:atIdx]
	}

	// Check for tag format (:tag) - but not registry port (host:port)
	// Scan backwards from end, stop at first / (which means we're in the repo part, not host part)
	for i := len(imageRef) - 1; i >= 0; i-- {
		if imageRef[i] == ':' {
			return imageRef[:i]
		}

		if imageRef[i] == '/' {
			break
		}
	}

	return imageRef
}

// CheckExists checks if an image exists in the destination registry.
func (syncer *Syncer) CheckExists(imageRef string) (bool, error) {
	exists, err := syncer.dstClient.CheckExists(imageRef)
	if err != nil {
		return false, fmt.Errorf("failed to check image existence: %w", err)
	}

	return exists, nil
}
