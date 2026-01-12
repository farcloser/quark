package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/buildctl"
	"github.com/farcloser/quark/internal/builder"
	"github.com/farcloser/quark/internal/utilities"
	"github.com/farcloser/quark/sdk/build"
	"github.com/farcloser/quark/sdk/platform"
)

type exportAction struct {
	*resource.BaseAction

	builder *Builder
	output  *Directory
	nodes   []*Node
	opts    *build.Options
}

func (ea *exportAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(ea, ea.BaseAction, name, out, copyFrom...)
}

// Execute performs the multi-platform build and exports to a local directory.
func (ea *exportAction) Execute(ctx context.Context) error {
	output := ea.output
	destPath := output.options.Path

	// Acquire a node slot via scheduler (blocks until available)
	node, err := defaultScheduler.Acquire(ctx, ea.nodes)
	if err != nil {
		return fmt.Errorf("%w: %w", build.ErrBuildFailed, err)
	}

	output.log.InfoContext(ctx, "starting export",
		slog.String("dest", destPath),
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
	opts := ea.buildOptions(destPath)

	// Prepare secrets
	preparedSecrets, err := ea.prepareSecrets()
	if err != nil {
		return fmt.Errorf("%w: %w", build.ErrBuildFailed, err)
	}

	defer func() {
		for _, s := range preparedSecrets {
			s.Release()
		}
	}()

	opts.Secrets = preparedSecrets

	// Build and export
	if _, err := client.Build(ctx, opts); err != nil {
		return fmt.Errorf("%w: %w", build.ErrBuildFailed, err)
	}

	output.log.InfoContext(ctx, "export complete",
		slog.String("dest", destPath),
		slog.String("node", node.Moniker()))

	return nil
}

// buildOptions constructs BuildOptions from the action's configuration.
func (ea *exportAction) buildOptions(destPath string) builder.BuildOptions {
	// Ensure opts is not nil
	if ea.opts == nil {
		ea.opts = &build.Options{}
	}

	// Default platforms if not specified
	platforms := ea.opts.Platforms
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
	for host, ip := range ea.opts.ExtraHosts {
		extraHosts = append(extraHosts, host+":"+ip.String())
	}

	return builder.BuildOptions{
		ContextPath:    ea.builder.options.Context,
		DockerfilePath: ea.builder.options.Dockerfile,
		Platforms:      platformStrs,
		DestPath:       destPath,
		BuildArgs:      utilities.MergeMaps(ea.builder.options.Args, ea.opts.Args),
		Target:         ea.opts.Target,
		ExtraHosts:     extraHosts,
		NoLog:          ea.opts.NoLog,
	}
}

// prepareSecrets prepares secret files from the merged secrets configuration.
func (ea *exportAction) prepareSecrets() ([]*builder.SecretFile, error) {
	// Merge base secrets from builder with per-build secrets (per-build overrides base)
	mergedSecrets := utilities.MergeMaps(ea.builder.options.Secrets, ea.opts.Secrets)

	var secretInputs []struct{ ID, Content string }
	for secretID, content := range mergedSecrets {
		secretInputs = append(secretInputs, struct{ ID, Content string }{ID: secretID, Content: content})
	}

	return builder.PrepareSecrets(secretInputs)
}
