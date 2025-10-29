package sdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/buildkit"
	"github.com/farcloser/quark/ssh"
)

var errNoBuildNodesConfigured = errors.New("no build nodes configured")

// Build represents a container image build operation.
type Build struct {
	name       string
	context    string
	dockerfile string
	nodes      []*BuildNode
	registry   *Registry
	tag        string
	log        zerolog.Logger
}

// BuildBuilder builds a Build.
type BuildBuilder struct {
	plan  *Plan
	build *Build
}

// Context sets the build context directory.
func (builder *BuildBuilder) Context(buildContext string) *BuildBuilder {
	builder.build.context = buildContext

	return builder
}

// Dockerfile sets the Dockerfile path.
func (builder *BuildBuilder) Dockerfile(dockerfile string) *BuildBuilder {
	builder.build.dockerfile = dockerfile

	return builder
}

// Node adds a build node.
func (builder *BuildBuilder) Node(node *BuildNode) *BuildBuilder {
	builder.build.nodes = append(builder.build.nodes, node)

	return builder
}

// Tag sets the image tag.
func (builder *BuildBuilder) Tag(tag string) *BuildBuilder {
	builder.build.tag = tag

	return builder
}

// Build validates and adds the build to the plan.
func (builder *BuildBuilder) Build() *Build {
	if builder.build.context == "" {
		builder.build.log.Fatal().Msg("build context is required")
	}

	if builder.build.dockerfile == "" {
		builder.build.dockerfile = "Dockerfile"
	}

	if len(builder.build.nodes) == 0 {
		builder.build.log.Fatal().Msg("at least one build node is required")
	}

	// Registry is optional for local builds
	// Multi-platform builds with --push require registry credentials

	if builder.build.tag == "" {
		builder.build.log.Fatal().Msg("build tag is required")
	}

	builder.plan.builds = append(builder.plan.builds, builder.build)

	return builder.build
}

func (build *Build) execute(ctx context.Context, sshPool *ssh.Pool) error {
	build.log.Info().
		Str("context", build.context).
		Str("tag", build.tag).
		Msg("building image")

	// Collect platforms from nodes
	platforms := make([]string, 0, len(build.nodes))
	for _, node := range build.nodes {
		platforms = append(platforms, node.platform.String())
	}

	// Use first node for multi-platform build
	// (buildx can handle multi-platform from single builder)
	if len(build.nodes) == 0 {
		return errNoBuildNodesConfigured
	}

	firstNode := build.nodes[0]

	sshClient, err := sshPool.GetClient(firstNode.endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to build node: %w", err)
	}

	// Create buildkit client
	bkClient := buildkit.NewClient(sshClient, build.log)

	// Upload build context
	remotePath := "/tmp/quark-build-" + build.name
	if err := bkClient.UploadContext(build.context, remotePath); err != nil {
		return fmt.Errorf("failed to upload build context: %w", err)
	}

	// Execute multi-platform build
	remoteDockerfile := fmt.Sprintf("%s/%s", remotePath, build.dockerfile)

	builtTag, err := bkClient.BuildMultiPlatform(
		ctx,
		remotePath,
		remoteDockerfile,
		platforms,
		build.tag,
	)
	if err != nil {
		return fmt.Errorf("failed to build image: %w", err)
	}

	build.log.Info().
		Str("tag", builtTag).
		Msg("build complete")

	return nil
}
