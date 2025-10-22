package sdk

import (
	"github.com/rs/zerolog"
)

// BuildNode represents an SSH-accessible buildkit node.
type BuildNode struct {
	name     string
	endpoint string
	platform Platform
	log      zerolog.Logger
}

// BuildNodeBuilder builds a BuildNode.
type BuildNodeBuilder struct {
	plan *Plan
	node *BuildNode
}

// Endpoint sets the SSH endpoint (IP, hostname, or SSH config alias).
func (builder *BuildNodeBuilder) Endpoint(endpoint string) *BuildNodeBuilder {
	builder.node.endpoint = endpoint

	return builder
}

// Platform sets the build platform.
func (builder *BuildNodeBuilder) Platform(platform Platform) *BuildNodeBuilder {
	builder.node.platform = platform

	return builder
}

// Build validates and adds the build node to the plan.
func (builder *BuildNodeBuilder) Build() *BuildNode {
	if builder.node.endpoint == "" {
		builder.node.log.Fatal().Msg("buildnode endpoint is required")
	}

	if builder.node.platform == "" {
		builder.node.log.Fatal().Msg("buildnode platform is required")
	}

	builder.plan.buildNodes = append(builder.plan.buildNodes, builder.node)

	return builder.node
}

// Name returns the node name.
func (node *BuildNode) Name() string {
	return node.name
}

// Endpoint returns the SSH endpoint.
func (node *BuildNode) Endpoint() string {
	return node.endpoint
}

// Platform returns the build platform.
func (node *BuildNode) Platform() Platform {
	return node.platform
}
