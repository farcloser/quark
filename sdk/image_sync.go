package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/internal/registry"
	"github.com/farcloser/quark/internal/syncer"
	"github.com/farcloser/quark/sdk/sync"
)

type syncAction struct {
	resource.BaseResource[syncAction]
	log    *slog.Logger
	source *Image
	dest   *Image
	opts   *sync.Options
}

func (sa *syncAction) Execute(ctx context.Context) error {
	// Audit can only scan by digest. Fail first if digest is NOT set
	if sa.source.ref.Digest == "" {
		return fmt.Errorf("%w: %s", sync.ErrArgumentRequiredImageDigest, sa.source.ref.String())
	}

	if sa.dest == nil {
		return fmt.Errorf("%w: %s", sync.ErrArgumentRequiredDestination, sa.source.ref.String())
	}

	srcClient := sa.createClient(sa.source.registry)
	dstClient := sa.createClient(sa.dest.registry)

	synch, _ := syncer.NewSyncer(srcClient, dstClient, sa.log)

	var platforms []string

	if sa.opts != nil {
		for _, p := range sa.opts.Platforms {
			platforms = append(platforms, p.String())
		}
	}

	dgst, err := synch.Image(ctx, *sa.source.ref, *sa.dest.ref, platforms)
	if err != nil {
		return fmt.Errorf("%w: %w", sync.ErrSyncFailed, err)
	}

	// Store the digest on the destination image
	sa.dest.ref.Digest = reference.Digest(dgst)

	sa.log.InfoContext(ctx, "image synced successfully",
		slog.String("source", sa.source.ref.String()),
		slog.String("dest", sa.dest.ref.String()),
		slog.String("digest", dgst))

	return nil
}

// createSourceClient creates a registry client for the source.
func (sa *syncAction) createClient(reg *Registry) *registry.Client {
	if reg != nil {
		return registry.NewClient(reg.credentials(), sa.log.With("component", "registry"))
	}

	return registry.NewClient(nil, sa.log.With("component", "registry"))
}
