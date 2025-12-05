package syncer

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/internal/registry"
)

// syncerImpl handles image synchronization between registries.
type syncerImpl struct {
	srcClient *registry.Client
	dstClient *registry.Client
	log       *slog.Logger
}

// Image synchronizes an image from source to destination.
// For multi-platform images, copies each platform separately and creates manifest list.
// The platforms parameter specifies which platforms to sync (e.g., []string{"linux/amd64", "linux/arm64"}).
// Returns the destination image digest (computed locally, not from registry for security).
func (syncer *syncerImpl) Image(
	ctx context.Context,
	srcImage, dstImage reference.ImageReference,
	platforms []string,
) (string, error) {
	syncer.log.DebugContext( //revive:disable-line:add-constant
		ctx,
		"starting image sync",
		"source",
		srcImage.String(),
		"destination",
		dstImage.String(),
		"platforms",
		platforms,
	)

	// Check if source exists and get descriptor
	desc, err := syncer.srcClient.GetImage(ctx, srcImage)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNotFound, err)
	}

	// Determine if this is an index (multi-platform) or single image
	if desc.MediaType.IsIndex() {
		syncer.log.DebugContext(ctx, "detected multi-platform image index") //revive:disable-line:add-constant

		return syncer.syncMultiPlatform(ctx, srcImage, dstImage, platforms)
	}

	syncer.log.DebugContext(ctx, "detected single-platform image") //revive:disable-line:add-constant

	return syncer.syncSinglePlatform(ctx, srcImage, dstImage)
}

// syncMultiPlatform syncs a multi-platform image by copying each platform separately.
// Returns the destination manifest list digest (computed locally for security).
func (syncer *syncerImpl) syncMultiPlatform(
	ctx context.Context,
	srcImage, dstImage reference.ImageReference,
	platforms []string,
) (string, error) {
	// Delegate to registry client which handles all the v1.Image operations internally
	digest, err := syncer.dstClient.SyncMultiPlatform(ctx, srcImage, dstImage, syncer.srcClient, platforms)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCreateManifestList, err)
	}

	syncer.log.DebugContext(
		ctx,
		"manifest list created successfully",
		"digest",
		digest,
	) //revive:disable-line:add-constant

	return digest, nil
}

// syncSinglePlatform syncs a single-platform image.
// Returns the destination image digest (computed locally for security).
func (syncer *syncerImpl) syncSinglePlatform(
	ctx context.Context,
	srcImage, dstImage reference.ImageReference,
) (string, error) {
	// CopyImage returns the digest directly (computed from source, not destination)
	digest, err := syncer.srcClient.CopyImage(ctx, srcImage, dstImage, syncer.dstClient)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCopyImage, err)
	}

	syncer.log.DebugContext(
		ctx,
		"single-platform image synced successfully",
		"digest",
		digest,
	) //revive:disable-line:add-constant

	return digest, nil
}
