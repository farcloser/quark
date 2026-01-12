package buildctl

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/dev/ssh"
	"github.com/farcloser/quark/dev/utilities"
	"github.com/farcloser/quark/internal/builder"
	"github.com/farcloser/quark/internal/docker"
)

// Client wraps buildctl operations via SSH-tunneled docker socket.
// It uses the docker-container:// scheme to communicate with buildkitd
// running in a container on the remote host.
type Client struct {
	dockerSocket *docker.ManagedSocket
	buildctlPath string
	log          *slog.Logger
}

// NewClient creates a new buildctl client using SSH socket tunneling.
// The client creates a local Unix socket that forwards to the remote Docker daemon.
// buildctl uses the docker-container:// scheme to communicate with buildkitd
// via docker exec, so no separate buildkit socket is needed.
// Multiple clients for the same connection share the underlying socket.
func NewClient(ctx context.Context, conn ssh.Connection, log *slog.Logger) (*Client, error) {
	// Ensure buildctl is installed (downloads from GitHub releases with checksum verification)
	buildctlPath, err := EnsureBuildctl(ctx, log)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrMissingRequirements, err)
	}

	// Acquire docker socket for managing buildkitd container and buildctl commands
	dockerSocket, err := docker.AcquireSocket(conn, log)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire docker socket: %w", err)
	}

	return &Client{
		dockerSocket: dockerSocket,
		buildctlPath: buildctlPath,
		log:          log,
	}, nil
}

// Close releases this client's reference to the socket.
// The socket is cleaned up when the last client releases it.
func (c *Client) Close() error {
	c.dockerSocket.Release()

	return nil
}

// Build builds container images for multiple platforms.
// If Tags is set, pushes to registry and returns the manifest digest.
// If DestPath is set, exports to local directory and returns empty string.
func (c *Client) Build(ctx context.Context, opts builder.BuildOptions) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", fault.ErrCancelled, err)
	}

	if err := c.ensureBuilder(ctx); err != nil {
		return "", err
	}

	args := c.buildBaseArgs(opts)

	// Determine output mode based on options
	if len(opts.Tags) > 0 {
		return c.buildAndPush(ctx, opts, args)
	}

	if opts.DestPath != "" {
		return "", c.buildToDirectory(ctx, opts, args)
	}

	return "", ErrNoOutput
}

// buildAndPush builds and pushes to registry, returning the manifest digest.
func (c *Client) buildAndPush(ctx context.Context, opts builder.BuildOptions, args []string) (string, error) {
	metadataFile := c.createMetadataFile()
	defer os.Remove(metadataFile)

	// Output configuration for pushing to registry
	outputOpts := "type=image,oci-mediatypes=true,compression=zstd,push=true"
	outputOpts += ",name=" + strings.Join(opts.Tags, ",name=")

	args = append(args, "--output", outputOpts)
	args = append(args, "--metadata-file", metadataFile)

	if err := c.runBuildctl(ctx, opts.NoLog, args...); err != nil {
		return "", fmt.Errorf("%w: %w", ErrBuildFailed, err)
	}

	digest, err := readBuildDigest(metadataFile)
	if err != nil {
		return "", err
	}

	return digest, nil
}

// buildToDirectory builds and exports to local directory.
func (c *Client) buildToDirectory(ctx context.Context, opts builder.BuildOptions, args []string) error {
	c.log.InfoContext(ctx, "starting build to directory",
		"platforms", opts.Platforms,
		"dest", opts.DestPath,
		"build_args", len(opts.BuildArgs))

	args = append(args, "--output", "type=local,dest="+opts.DestPath)

	if err := c.runBuildctl(ctx, opts.NoLog, args...); err != nil {
		return fmt.Errorf("%w: %w", ErrBuildFailed, err)
	}

	c.log.InfoContext(ctx, "build to directory complete", "dest", opts.DestPath)

	return nil
}

// buildBaseArgs constructs the common build arguments.
func (c *Client) buildBaseArgs(opts builder.BuildOptions) []string {
	args := []string{
		"build",
		"--frontend=dockerfile.v0",
		"--local", "context=" + opts.ContextPath,
		"--local", "dockerfile=" + filepath.Dir(opts.DockerfilePath),
	}

	// Set dockerfile name if not "Dockerfile"
	dockerfileName := filepath.Base(opts.DockerfilePath)
	if dockerfileName != "Dockerfile" {
		args = append(args, "--opt", "filename="+dockerfileName)
	}

	// Platforms
	if len(opts.Platforms) > 0 {
		args = append(args, "--opt", "platform="+strings.Join(opts.Platforms, ","))
	}

	// Build args
	for key, value := range opts.BuildArgs {
		args = append(args, "--opt", "build-arg:"+key+"="+value)
	}

	// Target stage
	if opts.Target != "" {
		args = append(args, "--opt", "target="+opts.Target)
	}

	// Extra hosts
	for _, host := range opts.ExtraHosts {
		args = append(args, "--opt", "add-host="+host)
	}

	// Secrets
	for _, secret := range opts.Secrets {
		args = append(args, "--secret", "id="+secret.ID+",src="+secret.Path)
	}

	// Attestations
	args = append(args, "--opt", "attest:sbom=true")
	args = append(args, "--opt", "attest:provenance=mode=max")

	return args
}

// buildMetadata represents the metadata output from buildctl.
type buildMetadata struct {
	//nolint:tagliatelle
	ContainerImageDigest string `json:"containerimage.digest"`
}

// readBuildDigest reads the image digest from the buildctl metadata file.
func readBuildDigest(metadataFile string) (string, error) {
	//nolint:gosec
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		return "", fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	var metadata buildMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return "", fmt.Errorf("%w: %w", fault.ErrInvalidJSON, err)
	}

	if metadata.ContainerImageDigest == "" {
		return "", ErrMetadataNoDigest
	}

	return metadata.ContainerImageDigest, nil
}

// ensureBuilder ensures the buildkitd daemon is running and ready on the remote host.
func (c *Client) ensureBuilder(ctx context.Context) error {
	manager := docker.NewBuildkitdManager(c.dockerSocket.DockerHost(), c.log)

	if err := manager.EnsureDaemon(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrEnsureBuilder, err)
	}

	// Wait for buildkitd to be ready to accept connections
	if err := c.waitForReady(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrEnsureBuilder, err)
	}

	return nil
}

const (
	readyTimeout      = 30 * time.Second
	readyPollInterval = 500 * time.Millisecond
)

// waitForReady polls buildkitd until it responds to debug workers command.
func (c *Client) waitForReady(ctx context.Context) error {
	deadline := time.Now().Add(readyTimeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", fault.ErrCancelled, ctx.Err())
		default:
		}

		cmd := exec.CommandContext(ctx, c.buildctlPath,
			"--addr", docker.BuildctlAddr(),
			"debug", "workers")
		cmd.Env = append(os.Environ(), "DOCKER_HOST="+c.dockerSocket.DockerHost())

		if err := cmd.Run(); err == nil {
			c.log.DebugContext(ctx, "buildkitd ready")

			return nil
		}

		time.Sleep(readyPollInterval)
	}

	return fmt.Errorf("%w within %v", ErrBuildkitdNotReady, readyTimeout)
}

// createMetadataFile creates a unique file path for build metadata in the node's runtime directory.
func (c *Client) createMetadataFile() string {
	// Use the node's socket directory for metadata files
	socketDir := filepath.Dir(c.dockerSocket.SocketPath())

	// Generate random suffix to avoid collisions between concurrent builds
	filename := fmt.Sprintf("build-%s.json", utilities.GenerateProcessToken())

	return filepath.Join(socketDir, filename)
}

// runBuildctl executes a buildctl command.
// Uses docker-container:// scheme which communicates via docker exec.
func (c *Client) runBuildctl(ctx context.Context, quiet bool, args ...string) error {
	// Prepend the --addr flag using docker-container:// scheme
	fullArgs := append([]string{"--addr", docker.BuildctlAddr()}, args...)

	c.log.DebugContext(ctx, "executing buildctl command",
		"command", c.buildctlPath+" "+strings.Join(fullArgs, " "))

	//nolint:gosec
	cmd := exec.CommandContext(ctx, c.buildctlPath, fullArgs...)

	// Set DOCKER_HOST so docker-container:// scheme uses our tunneled socket
	cmd.Env = append(os.Environ(), "DOCKER_HOST="+c.dockerSocket.DockerHost())

	if !quiet {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %w", fault.ErrCommandFailure, err)
	}

	return nil
}
