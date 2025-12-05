package sdk

import (
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/sdk/build"
	"github.com/farcloser/quark/sdk/lint"
)

// Builder represents a build configuration.
type Builder struct {
	resource.BaseResource[Builder]
	opts BuildOpts
}

// BuildOpts contains configuration options for creating a builder.
type BuildOpts struct {
	Context    string
	Dockerfile string
}

// NewBuilder creates a new Builder with the given options.
func NewBuilder(opts BuildOpts) *Builder {
	b := &Builder{
		opts: opts,
	}
	b.BaseResource = resource.NewBaseResource(b, "builder")

	return b
}

// Build builds an image on one of the provided nodes and returns the built image.
// The least busy node with available capacity is selected; if all nodes are at capacity,
// the build blocks until a slot becomes available.
// The returned Image depends on the build completing.
func (b *Builder) Build(img *Image, nodes []*Node, opts *build.Options) *Image {
	action := &buildAction{
		log:     slog.With("action", "build", "image", img.ResourceName()),
		builder: b,
		image:   img,
		nodes:   nodes,
		opts:    opts,
	}
	action.BaseResource = resource.NewBaseResource(action, "build:"+img.ResourceName())
	action.DependsOn(b)
	action.DependsOn(img)

	// Depend on all nodes so they are initialized before build
	for _, node := range nodes {
		action.DependsOn(node)
	}

	result := &Image{
		opts:     img.opts,
		registry: img.registry,
	}
	result.BaseResource = resource.NewBaseResource(result, img.ResourceName())
	result.DependsOn(action)

	return result
}

// Lint lints the builder's Dockerfile using godolint.
// Returns the builder for chaining; the scan result is available after execution.
func (b *Builder) Lint(opts *lint.Options) *Builder {
	action := &buildLintAction{
		log:     slog.With("action", "scan", "dockerfile", b.opts.Dockerfile),
		builder: b,
		opts:    opts,
	}
	action.BaseResource = resource.NewBaseResource(action, "scan:"+b.opts.Dockerfile)
	action.DependsOn(b)

	// Create a result builder that depends on the scan completing
	result := &Builder{
		opts: b.opts,
	}
	result.BaseResource = resource.NewBaseResource(result, b.ResourceName())
	result.DependsOn(action)

	return result
}
