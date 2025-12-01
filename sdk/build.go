package sdk

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/buildkit"
	"github.com/farcloser/quark/ssh"
)

// BuildArgs contains configuration options for creating a build operation.
type BuildArgs struct {
	Name       string        // Required - operation name
	Context    string        // Required - build context directory
	Dockerfile string        // Optional - Dockerfile path (default: "Dockerfile")
	Nodes      []*BuildNode  // Required - at least one build node
	Tag        string        // Required - image tag
	Timeout    time.Duration // Optional - operation timeout
}

// build represents a container image build operation.
type build struct {
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

func (b *build) execute(ctx context.Context) error {
	// Apply timeout if configured
	if b.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.timeout)
		defer cancel()
	}

	b.log.Info().
		Str("context", b.context).
		Str("tag", b.tag).
		Msg("building image")

	// Collect platforms from nodes
	platforms := make([]string, 0, len(b.nodes))
	for _, node := range b.nodes {
		platforms = append(platforms, node.platform.String())
	}

	// Use first node for multi-platform build
	// (buildx can handle multi-platform from single builder)
	if len(b.nodes) == 0 {
		return ErrNoBuildNodesConfigured
	}

	firstNode := b.nodes[0]

	sshClient, err := b.sshPool.GetClient(firstNode.endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to build node: %w", err)
	}

	// Create buildkit client
	bkClient := buildkit.NewClient(sshClient, b.log)

	// Create unique remote directory for build context
	remotePathRaw, _, err := sshClient.Execute("mktemp -d -t quark-build-XXXXXX")
	if err != nil {
		return fmt.Errorf("failed to create remote build directory: %w", err)
	}

	remotePath := strings.TrimSpace(remotePathRaw)

	// Upload build context
	if err := bkClient.UploadContext(ctx, b.context, remotePath); err != nil {
		return fmt.Errorf("failed to upload build context: %w", err)
	}

	// Execute multi-platform build
	remoteDockerfile := fmt.Sprintf("%s/%s", remotePath, b.dockerfile)

	builtTag, err := bkClient.BuildMultiPlatform(
		ctx,
		remotePath,
		remoteDockerfile,
		platforms,
		b.tag,
	)
	if err != nil {
		return fmt.Errorf("failed to build image: %w", err)
	}

	b.log.Info().
		Str("tag", builtTag).
		Msg("build complete")

	return nil
}

// operationName returns the build operation name (implements operation interface).
func (b *build) operationName() string {
	return b.opName
}
