package sdk

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/registry"
	syncsvc "github.com/farcloser/quark/internal/sync"
)

// SyncArgs contains configuration options for creating a sync operation.
type SyncArgs struct {
	Description string     // Required - operation name
	Source      *Image     // Required - source image (must have digest)
	Destination *Image     // Required - destination image
	Platforms   []Platform // Optional - platforms to sync (default: AMD64, ARM64)
}

// syncOp represents an image sync operation from source to destination registry.
type syncOp struct {
	opName         string
	sourceRegistry *Registry
	sourceImage    *Image
	destRegistry   *Registry
	destImage      *Image
	platforms      []Platform
	log            zerolog.Logger
}

func (s *syncOp) execute(ctx context.Context) error {
	// Use digestRef for source (immutable, secure)
	sourceRef, err := s.sourceImage.digestRef()
	if err != nil {
		return fmt.Errorf("failed to build source reference: %w", err)
	}

	// Use tagRef for destination (includes domain/name:version)
	destRef := s.destImage.tagRef()

	s.log.Info().
		Str("source", sourceRef).
		Str("destination", destRef).
		Msg("syncing image")

	// Create source registry client
	// If no registry provided, use empty credentials (for public images)
	// Registry host will be inferred from image name by go-containerregistry
	var srcClient *registry.Client
	if s.sourceRegistry != nil {
		srcClient = registry.NewClient(
			s.sourceRegistry.domain,
			s.sourceRegistry.username,
			s.sourceRegistry.token,
			s.log.With().Str("registry", "source").Logger(),
		)
	} else {
		// No auth - for public images
		srcClient = registry.NewClient(
			"", // Host inferred from image name
			"", // No username
			"", // No password
			s.log.With().Str("registry", "source").Logger(),
		)
	}

	var dstClient *registry.Client
	if s.destRegistry != nil {
		dstClient = registry.NewClient(
			s.destRegistry.domain,
			s.destRegistry.username,
			s.destRegistry.token,
			s.log.With().Str("registry", "destination").Logger(),
		)
	} else {
		// No auth - attempting to push without credentials will fail
		dstClient = registry.NewClient(
			"", // Host inferred from image name
			"", // No username
			"", // No password
			s.log.With().Str("registry", "destination").Logger(),
		)
	}

	// Create syncer
	syncer := syncsvc.NewSyncer(srcClient, dstClient, s.log)

	// Sync the image by digest and capture destination digest
	destDigest, err := syncer.SyncImage(ctx, sourceRef, destRef)
	if err != nil {
		return fmt.Errorf("failed to sync image: %w", err)
	}

	// Auto-populate destination image digest for subsequent operations (e.g., scanning)
	if err := s.destImage.SetDigest(destDigest); err != nil {
		return fmt.Errorf("failed to set destination digest: %w", err)
	}

	s.log.Info().
		Str("dest_digest", destDigest).
		Msg("image sync complete")

	return nil
}

// operationName returns the sync operation name (implements operation interface).
func (s *syncOp) operationName() string {
	return s.opName
}
