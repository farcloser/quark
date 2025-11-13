package sdk

import (
	"strings"

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
	plan  *Plan
	node  *BuildNode
	built bool
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
// The builder becomes unusable after Build() is called.
// Create a new builder for each operation.
func (builder *BuildNodeBuilder) Build() (*BuildNode, error) {
	if builder.built {
		return nil, ErrBuilderAlreadyUsed
	}

	builder.built = true

	builder.node.endpoint = strings.TrimSpace(builder.node.endpoint)
	if builder.node.endpoint == "" {
		return nil, ErrBuildNodeEndpointRequired
	}

	if builder.node.platform == (Platform{}) {
		return nil, ErrBuildNodePlatformRequired
	}

	builder.plan.buildNodes = append(builder.plan.buildNodes, builder.node)

	return builder.node, nil
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
