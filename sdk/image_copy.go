package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/internal/syncer"
	"github.com/farcloser/quark/sdk/platform"
	"github.com/farcloser/quark/sdk/sync"
)

type copyAction struct {
	*resource.BaseAction

	opts   *sync.Options
	source *Image
	dest   *Image
	output *Image
}

func (ca *copyAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(ca, ca.BaseAction, name, out, copyFrom...)
}

func (ca *copyAction) Execute(ctx context.Context) error {
	source := ca.source
	output := ca.output

	// Copy can only copy by digest. Fail first if digest is NOT set
	if source.ref.Digest == "" {
		return fmt.Errorf("%w: %s", sync.ErrArgumentRequiredImageDigest, source.ref.String())
	}

	if ca.dest == nil {
		return fmt.Errorf("%w: %s", sync.ErrArgumentRequiredDestination, source.ref.String())
	}

	srcClient := ca.createClient(source.registry, output.log)
	dstClient := ca.createClient(ca.dest.registry, output.log)

	synch, _ := syncer.NewSyncer(srcClient, dstClient, output.log)

	// Ensure opts is not nil
	if ca.opts == nil {
		ca.opts = &sync.Options{}
	}

	// Default platforms if not specified
	if ca.opts.Platforms == nil {
		ca.opts.Platforms = []*platform.Platform{platform.ARM64, platform.AMD64}
	}

	var platforms []string

	for _, p := range ca.opts.Platforms {
		platforms = append(platforms, p.String())
	}

	dgst, err := synch.Image(ctx, *source.ref, *ca.dest.ref, platforms)
	if err != nil {
		return fmt.Errorf("%w: %w", sync.ErrSyncFailed, err)
	}

	// Store the digest on the output image
	output.ref.Digest = reference.Digest(dgst)

	output.log.InfoContext(ctx, "image copied successfully",
		slog.String("source", source.ref.String()),
		slog.String("dest", output.ref.String()),
		slog.String("digest", dgst))

	return nil
}

// createClient creates a registry client.
func (*copyAction) createClient(reg *Registry, log *slog.Logger) *registry.Client {
	if reg != nil {
		return registry.NewClient(reg.credentials(), log)
	}

	return registry.NewClient(nil, log)
}
