package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/buildctl"
	"github.com/farcloser/quark/internal/builder"
	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/internal/utilities"
	"github.com/farcloser/quark/sdk/build"
	"github.com/farcloser/quark/sdk/platform"
)

type buildAction struct {
	*resource.BaseAction

	builder *Builder
	output  *Image
	nodes   []*Node
	opts    *build.Options
}

func (ba *buildAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(ba, ba.BaseAction, name, out, copyFrom...)
}

// Execute performs the multi-platform build.
func (ba *buildAction) Execute(ctx context.Context) error {
	output := ba.output
	imageTag := output.ref.String()

	// Acquire a node slot via scheduler (blocks until available)
	node, err := defaultScheduler.Acquire(ctx, ba.nodes)
	if err != nil {
		return fmt.Errorf("%w: %w", build.ErrBuildFailed, err)
	}

	output.log.InfoContext(ctx, "starting build",
		slog.String("image", imageTag),
		slog.String("node", node.Moniker()))

	// Create builder client using node's SSH connection
	client, err := buildctl.NewClient(ctx, node.Connection(), output.log)
	if err != nil {
		defaultScheduler.Release(node)

		return fmt.Errorf("%w: %w", build.ErrBuildFailed, err)
	}

	// CRITICAL: Release scheduler slot BEFORE closing client.
	// This allows queued builds to acquire the socket and keep it alive,
	// preventing client.Close() from blocking on socket shutdown.
	defer client.Close()
	defer defaultScheduler.Release(node)

	// Build options
	opts := ba.buildOptions(imageTag)

	// Prepare secrets
	preparedSecrets, err := ba.prepareSecrets()
	if err != nil {
		return fmt.Errorf("%w: %w", build.ErrBuildFailed, err)
	}

	defer func() {
		for _, s := range preparedSecrets {
			s.Release()
		}
	}()

	opts.Secrets = preparedSecrets

	// Build and push
	dgst, err := client.Build(ctx, opts)
	if err != nil {
		return fmt.Errorf("%w: %w", build.ErrBuildFailed, err)
	}

	// Store the digest on the output image
	output.ref.Digest = reference.Digest(dgst)

	output.log.InfoContext(ctx, "build complete",
		slog.String("image", imageTag),
		slog.String("node", node.Moniker()),
		slog.String("digest", dgst))

	return nil
}

// buildOptions constructs BuildOptions from the action's configuration.
func (ba *buildAction) buildOptions(imageTag string) builder.BuildOptions {
	// Ensure opts is not nil
	if ba.opts == nil {
		ba.opts = &build.Options{}
	}

	// Default platforms if not specified
	platforms := ba.opts.Platforms
	if platforms == nil {
		platforms = []*platform.Platform{platform.ARM64, platform.AMD64}
	}

	// Convert platforms to strings
	var platformStrs []string

	for _, p := range platforms {
		if p != nil {
			platformStrs = append(platformStrs, p.String())
		}
	}

	// Convert extra hosts to strings
	var extraHosts []string
	for host, ip := range ba.opts.ExtraHosts {
		extraHosts = append(extraHosts, host+":"+ip.String())
	}

	return builder.BuildOptions{
		ContextPath:    ba.builder.options.Context,
		DockerfilePath: ba.builder.options.Dockerfile,
		Platforms:      platformStrs,
		Tags:           []string{imageTag},
		BuildArgs:      utilities.MergeMaps(ba.builder.options.Args, ba.opts.Args),
		Target:         ba.opts.Target,
		ExtraHosts:     extraHosts,
		NoLog:          ba.opts.NoLog,
	}
}

// prepareSecrets prepares secret files from the merged secrets configuration.
func (ba *buildAction) prepareSecrets() ([]*builder.SecretFile, error) {
	// Merge base secrets from builder with per-build secrets (per-build overrides base)
	mergedSecrets := utilities.MergeMaps(ba.builder.options.Secrets, ba.opts.Secrets)

	var secretInputs []struct{ ID, Content string }
	for secretID, content := range mergedSecrets {
		secretInputs = append(secretInputs, struct{ ID, Content string }{ID: secretID, Content: content})
	}

	return builder.PrepareSecrets(secretInputs)
}
