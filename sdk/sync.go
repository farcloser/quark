package sdk

import (
	"context"
	"fmt"

	"github.com/opencontainers/go-digest"
	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/registry"
	syncsvc "github.com/farcloser/quark/internal/sync"
)

// Sync represents an image sync operation from source to destination registry.
type Sync struct {
	opName         string
	sourceRegistry *Registry
	sourceImage    *Image
	destRegistry   *Registry
	destImage      *Image
	platforms      []Platform
	destDigest     string // Destination image digest (computed locally, not from registry)
	log            zerolog.Logger
}

// SyncBuilder builds a Sync.
type SyncBuilder struct {
	plan *Plan
	sync *Sync
}

// Source sets the source image.
// The image MUST have a digest specified - syncing by tag alone is not allowed for security.
// Registry credentials are looked up from the plan's registry collection using the image domain.
// If no registry is found for the domain, unauthenticated access will be used.
func (builder *SyncBuilder) Source(image *Image) *SyncBuilder {
	builder.sync.sourceImage = image
	builder.sync.sourceRegistry = builder.plan.getRegistry(image.Domain())

	return builder
}

// Destination sets the destination image.
// The image should have name, domain, and version. Digest will be computed after sync.
// Registry credentials are looked up from the plan's registry collection using the image domain.
// If no registry is found for the domain, unauthenticated access will be used.
func (builder *SyncBuilder) Destination(image *Image) *SyncBuilder {
	builder.sync.destImage = image
	builder.sync.destRegistry = builder.plan.getRegistry(image.Domain())

	return builder
}

// Platforms sets the platforms to sync.
func (builder *SyncBuilder) Platforms(platforms ...Platform) *SyncBuilder {
	builder.sync.platforms = platforms

	return builder
}

// Build validates and adds the sync to the plan.
func (builder *SyncBuilder) Build() (*Sync, error) {
	if builder.sync.sourceImage == nil {
		return nil, ErrSyncSourceRequired
	}

	if builder.sync.sourceImage.Digest() == "" {
		return nil, fmt.Errorf("%w for image %q", ErrSyncSourceDigestRequired, builder.sync.sourceImage.Name())
	}

	if builder.sync.destImage == nil {
		return nil, ErrSyncDestinationRequired
	}

	if len(builder.sync.platforms) == 0 {
		// Default to both platforms
		builder.sync.platforms = []Platform{PlatformAMD64, PlatformARM64}
	}

	builder.plan.syncs = append(builder.plan.syncs, builder.sync)
	builder.plan.operations = append(builder.plan.operations, builder.sync)

	return builder.sync, nil
}

func (sync *Sync) execute(_ context.Context) error {
	// Use digestRef for source (immutable, secure)
	sourceRef, err := sync.sourceImage.digestRef()
	if err != nil {
		return fmt.Errorf("failed to build source reference: %w", err)
	}

	// Use tagRef for destination (includes domain/name:version)
	destRef, err := sync.destImage.tagRef()
	if err != nil {
		return fmt.Errorf("failed to build destination reference: %w", err)
	}

	sync.log.Info().
		Str("source", sourceRef).
		Str("destination", destRef).
		Msg("syncing image")

	// Create source registry client
	// If no registry provided, use empty credentials (for public images)
	// Registry host will be inferred from image name by go-containerregistry
	var srcClient *registry.Client
	if sync.sourceRegistry != nil {
		srcClient = registry.NewClient(
			sync.sourceRegistry.host,
			sync.sourceRegistry.username,
			sync.sourceRegistry.password,
			sync.log.With().Str("registry", "source").Logger(),
		)
	} else {
		// No auth - for public images
		srcClient = registry.NewClient(
			"", // Host inferred from image name
			"", // No username
			"", // No password
			sync.log.With().Str("registry", "source").Logger(),
		)
	}

	var dstClient *registry.Client
	if sync.destRegistry != nil {
		dstClient = registry.NewClient(
			sync.destRegistry.host,
			sync.destRegistry.username,
			sync.destRegistry.password,
			sync.log.With().Str("registry", "destination").Logger(),
		)
	} else {
		// No auth - attempting to push without credentials will fail
		dstClient = registry.NewClient(
			"", // Host inferred from image name
			"", // No username
			"", // No password
			sync.log.With().Str("registry", "destination").Logger(),
		)
	}

	// Create syncer
	syncer := syncsvc.NewSyncer(srcClient, dstClient, sync.log)

	// Sync the image by digest and capture destination digest
	destDigest, err := syncer.SyncImage(sourceRef, destRef)
	if err != nil {
		return fmt.Errorf("failed to sync image: %w", err)
	}

	// Store the destination digest (computed locally for security)
	sync.destDigest = destDigest

	// Auto-populate destination image digest for subsequent operations (e.g., scanning)
	// Update the internal reference digest
	parsedDigest, err := digest.Parse(destDigest)
	if err != nil {
		return fmt.Errorf("failed to parse computed digest: %w", err)
	}

	sync.destImage.ref.Digest = parsedDigest

	sync.log.Info().
		Str("dest_digest", destDigest).
		Msg("image sync complete")

	return nil
}

// DestDigest returns the destination image digest after sync execution.
// The digest is computed locally from the pushed image/manifest, not retrieved
// from the registry, providing defense in depth against compromised registries.
// Returns empty string if sync has not been executed yet.
func (sync *Sync) DestDigest() string {
	return sync.destDigest
}

// operationName returns the sync operation name (implements operation interface).
func (sync *Sync) operationName() string {
	return sync.opName
}
