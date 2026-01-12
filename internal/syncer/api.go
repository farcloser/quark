package syncer

import (
	"context"
	"log/slog"

	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/farcloser/quark/internal/reference"
)

// Syncer handles image synchronization between registries.
type Syncer interface {
	Image(ctx context.Context, srcImage, dstImage reference.ImageReference, platforms []string) (string, error)
}

// NewSyncer creates a new image syncer.
func NewSyncer(srcClient, dstClient *registry.Client, log *slog.Logger) (Syncer, error) {
	return &syncerImpl{
		srcClient: srcClient,
		dstClient: dstClient,
		log:       log.With("component", "syncer"),
	}, nil
}
