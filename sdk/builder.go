package sdk

import (
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/analyze/dockerfile"
	"github.com/farcloser/quark/sdk/build"
	sdklog "github.com/farcloser/quark/sdk/logger"
	"github.com/farcloser/quark/sdk/policy"
)

// Builder represents a build configuration.
type Builder struct {
	resource.Resource

	options BuilderOpts
	log     *slog.Logger

	// Results from previous actions (populated during execution)
	lintResult *dockerfile.Result
}

// BuilderOpts contains configuration options for creating a builder.
type BuilderOpts struct {
	// Moniker holds plan-defined metadata used purely for display
	Moniker    string
	Context    string
	Dockerfile string

	// Args are base build arguments that apply to all builds from this builder.
	// These can be overridden per-build via build.Options.Args.
	Args map[string]string

	// Secrets are base secrets that apply to all builds from this builder.
	// These can be overridden per-build via build.Options.Secrets.
	Secrets map[string]string
}

// NewBuilder creates a new Builder with the given options.
func NewBuilder(opts BuilderOpts) *Builder {
	moniker := opts.Moniker
	if moniker == "" {
		moniker = opts.Dockerfile
	}

	output := &Builder{
		options: opts,
		log:     slog.With(builderResourceName, moniker),
	}

	moniker = fmt.Sprintf("%s:%s", builderResourceName, moniker)

	output.Resource = (&createBuilderAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionCreateName, moniker)),
		output:     output,
	}).AddOutput(moniker, output)

	return output
}

// Moniker returns the builder name.
func (b *Builder) Moniker() string {
	moniker := b.options.Moniker
	if moniker == "" {
		moniker = b.options.Dockerfile
	}

	return fmt.Sprintf("%s:%s", builderResourceName, moniker)
}

// Copy copies this builder's runtime state to another builder.
func (b *Builder) Copy(dest resource.Resource) error {
	destBuilder, ok := dest.(*Builder)
	if !ok {
		b.log.Error("Copy: destination is not a Builder, skipping", "dest", fmt.Sprintf("%T", dest))

		return nil
	}

	// Copy action results for policy evaluation
	destBuilder.lintResult = b.lintResult

	return nil
}

// Build builds an image on one of the provided nodes and pushes to registry.
// The least busy node with available capacity is selected; if all nodes are at capacity,
// the build blocks until a slot becomes available.
// Returns the built image with digest populated.
func (b *Builder) Build(img *Image, nodes []*Node, opts *build.Options) *Image {
	// Collect dependencies: builder, image, and all nodes
	deps := []resource.Resource{b, img}
	for _, node := range nodes {
		deps = append(deps, node)
	}

	output := &Image{
		options:  img.options,
		log:      img.log,
		registry: img.registry,
	}

	output.Resource = (&buildAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionBuildName, output.Moniker()), deps...),
		builder:    b,
		nodes:      nodes,
		opts:       opts,
		output:     output,
	}).AddOutput(img.options.Name, output, img)

	return output
}

// Export builds and exports to a local directory on one of the provided nodes.
// The least busy node with available capacity is selected; if all nodes are at capacity,
// the build blocks until a slot becomes available.
// Returns the directory with the exported build output.
func (b *Builder) Export(dir *Directory, nodes []*Node, opts *build.Options) *Directory {
	// Collect dependencies: builder, directory, and all nodes
	deps := []resource.Resource{b, dir}
	for _, node := range nodes {
		deps = append(deps, node)
	}

	output := &Directory{
		options: dir.options,
		log:     dir.log,
	}

	output.Resource = (&exportAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionExportName, output.Moniker()), deps...),
		builder:    b,
		nodes:      nodes,
		opts:       opts,
		output:     output,
	}).AddOutput(output.Moniker(), output, dir)

	return output
}

// Lint lints the builder's Dockerfile using godolint.
// This action only populates lint results - use Check() with a policy for enforcement
// and Log() for display formatting.
// Returns a new Builder representing the post-lint state with results populated.
func (b *Builder) Lint() *Builder {
	output := &Builder{
		options: b.options,
		log:     b.log,
	}

	output.Resource = (&lintAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionLintName, output.Moniker()), b),
		builder:    b,
		output:     output,
	}).AddOutput(output.Moniker(), output, b)

	return output
}

// Check schedules a policy check on the builder.
// The policy is evaluated against the builder's current state, including
// results from previous actions (Lint).
// Returns a new Builder representing the post-check state.
func (b *Builder) Check(pol policy.Policy) *Builder {
	output := &Builder{
		options: b.options,
		log:     b.log,
	}

	output.Resource = (&builderCheckAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionCheckName, output.Moniker()), b),
		policy:     pol,
		input:      b,
		output:     output,
	}).AddOutput(output.Moniker(), output, b)

	return output
}

// Log schedules logging of lint results attached to the builder.
// Results are formatted and output to the logger based on the configured
// severity-to-log-level mapping.
// Returns a new Builder representing the post-log state.
func (b *Builder) Log(opts *sdklog.Options) *Builder {
	output := &Builder{
		options: b.options,
		log:     b.log,
	}

	output.Resource = (&builderLogAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionLogName, output.Moniker()), b),
		opts:       opts,
		output:     output,
	}).AddOutput(output.Moniker(), output, b)

	return output
}

// With creates a new Builder that depends on the current builder and additional resources.
// Use this to express ordering constraints when there's no direct data dependency.
// Returns a new Builder for chaining.
func (b *Builder) With(deps ...resource.Resource) *Builder {
	output := &Builder{
		options: b.options,
		log:     b.log,
	}

	output.Resource = resource.NewWithAction("with:"+b.Moniker(), b, deps...).
		AddOutput(b.Moniker(), output, b)

	return output
}
