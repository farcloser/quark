package sdk

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/buildkit"
	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/sdk/build"
)

const nodeSelectInterval = 1 * time.Second

type buildAction struct {
	resource.BaseResource[buildAction]

	log     *slog.Logger
	builder *Builder
	image   *Image
	nodes   []*Node
	opts    *build.Options
}

// Execute performs the multi-platform build.
func (ba *buildAction) Execute(ctx context.Context) error {
	// Validate required nodes
	if len(ba.nodes) == 0 {
		return build.ErrNodeRequired
	}

	imageTag := ba.image.ref.String()

	// Select and acquire a node
	node, err := ba.acquireNode(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", build.ErrBuildFailed, err)
	}
	defer node.Release()

	ba.log.InfoContext(ctx, "starting build",
		slog.String("image", imageTag),
		slog.String("node", node.ResourceName()))

	// Create buildkit client using node's SSH connection
	client, err := buildkit.NewClient(node.Connection(), node.ResourceName(), ba.log)
	if err != nil {
		return fmt.Errorf("%w: %w", build.ErrBuildFailed, err)
	}
	defer client.Close()

	// Login to registry if credentials are available
	if ba.image.registry != nil && ba.image.registry.opts.Username != "" {
		if err := client.RegistryLogin(ctx,
			ba.image.registry.opts.Domain,
			ba.image.registry.opts.Username,
			ba.image.registry.opts.Token,
		); err != nil {
			return fmt.Errorf("%w: registry login: %w", build.ErrBuildFailed, err)
		}
	}

	// Convert platforms to strings
	var platforms []string

	if ba.opts != nil {
		for _, p := range ba.opts.Platforms {
			if p != nil {
				platforms = append(platforms, p.String())
			}
		}
	}

	// Get build args
	var args map[string]string
	if ba.opts != nil {
		args = ba.opts.Args
	}

	// Build multi-platform and push
	dgst, err := client.BuildMultiPlatform(ctx,
		ba.builder.opts.Context,
		ba.builder.opts.Dockerfile,
		platforms,
		[]string{imageTag},
		args,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", build.ErrBuildFailed, err)
	}

	// Store the digest on the image
	ba.image.ref.Digest = reference.Digest(dgst)

	ba.log.InfoContext(ctx, "build complete",
		slog.String("image", imageTag),
		slog.String("node", node.ResourceName()),
		slog.String("digest", dgst))

	return nil
}

// acquireNode selects and acquires a build slot on the least busy node.
// If all nodes are at capacity, it blocks until a slot becomes available.
func (ba *buildAction) acquireNode(ctx context.Context) (*Node, error) {
	for {
		// Try to acquire the least busy node without blocking
		node := ba.selectLeastBusy()
		if node != nil && node.TryAcquire() {
			return node, nil
		}

		// All nodes at capacity - wait and retry
		select {
		case <-ctx.Done():
			return nil, ctx.Err() //nolint:wrapcheck // context errors are self-explanatory sentinels
		case <-time.After(nodeSelectInterval): // Retry selection
		}
	}
}

// selectLeastBusy returns the node with the most available capacity.
// Returns nil if no nodes have available slots.
func (ba *buildAction) selectLeastBusy() *Node {
	var best *Node

	bestAvailable := 0

	for _, node := range ba.nodes {
		available := node.Available()
		if available > bestAvailable {
			best = node
			bestAvailable = available
		}
	}

	return best
}
