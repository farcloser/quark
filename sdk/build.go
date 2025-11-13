package sdk

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/buildkit"
	"github.com/farcloser/quark/ssh"
)

// Build represents a container image build operation.
type Build struct {
	opName     string
	context    string
	dockerfile string
	nodes      []*BuildNode
	tag        string
	timeout    time.Duration
	log        zerolog.Logger

	// sshPool is set by executor before execution
	sshPool *ssh.Pool
}

// BuildBuilder builds a Build.
type BuildBuilder struct {
	plan  *Plan
	build *Build
	built bool
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

// Timeout sets the operation timeout.
// If not set, the operation will use the context timeout from Plan.Execute().
func (builder *BuildBuilder) Timeout(duration time.Duration) *BuildBuilder {
	builder.build.timeout = duration

	return builder
}

// Build validates and adds the build to the plan.
// The builder becomes unusable after Build() is called.
// Create a new builder for each operation.
func (builder *BuildBuilder) Build() (*Build, error) {
	if builder.built {
		return nil, ErrBuilderAlreadyUsed
	}

	builder.built = true

	if builder.build.context == "" {
		return nil, ErrBuildContextRequired
	}

	if builder.build.dockerfile == "" {
		builder.build.dockerfile = "Dockerfile"
	}

	if len(builder.build.nodes) == 0 {
		return nil, ErrBuildNodeRequired
	}

	// Registry is optional for local builds
	// Multi-platform builds with --push require registry credentials

	if builder.build.tag == "" {
		return nil, ErrBuildTagRequired
	}

	builder.plan.builds = append(builder.plan.builds, builder.build)
	builder.plan.operations = append(builder.plan.operations, builder.build)

	return builder.build, nil
}

func (build *Build) execute(ctx context.Context) error {
	// Apply timeout if configured
	if build.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, build.timeout)
		defer cancel()
	}

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
		return ErrNoBuildNodesConfigured
	}

	firstNode := build.nodes[0]

	sshClient, err := build.sshPool.GetClient(firstNode.endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to build node: %w", err)
	}

	// Create buildkit client
	bkClient := buildkit.NewClient(sshClient, build.log)

	// Upload build context
	remotePath := "/tmp/quark-build-" + build.opName
	if err := bkClient.UploadContext(ctx, build.context, remotePath); err != nil {
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

// operationName returns the build operation name (implements operation interface).
func (build *Build) operationName() string {
	return build.opName
}
