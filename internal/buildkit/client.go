package buildkit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.farcloser.world/core/filesystem"

	"github.com/farcloser/quark/dev/ssh"
	"github.com/farcloser/quark/internal/utils"
)

const (
	// builderName is the name of the buildx builder instance used for multi-platform builds.
	builderName = "quark-builder"

	// remoteDockerSocket is the path to the Docker socket on the remote host.
	remoteDockerSocket = "/var/run/docker.sock"

	// dockerCmd is the docker command name.
	dockerCmd = "docker"

	// buildxSubCmd is the buildx subcommand.
	buildxSubCmd = "buildx"

	// socketDirPerms is the permission mode for the socket directory.
	socketDirPerms = 0o700

	// socketDialTimeout is how long to wait when checking if a socket is alive.
	socketDialTimeout = 100 * time.Millisecond
)

// Client wraps Docker buildx operations via SSH-tunneled socket.
type Client struct {
	sshConn    ssh.Connection
	log        *slog.Logger
	socketPath string
	ownsSocket bool         // true if this client created the socket and is responsible for cleanup
	listener   net.Listener // nil if ownsSocket is false
	wg         sync.WaitGroup
	closed     chan struct{}
}

// NewClient creates a new buildkit client using SSH socket tunneling.
// The client creates a local Unix socket that forwards to the remote Docker daemon.
// The nodeID is used to create a stable socket path based on the node's identity.
// If another client already owns the socket for this node, the returned client
// will reuse the existing socket without creating a new listener.
func NewClient(sshConn ssh.Connection, nodeID string, log *slog.Logger) (*Client, error) {
	// Create socket path under runtime directory using hash of node ID
	hash := sha256.Sum256([]byte(nodeID))
	hashStr := hex.EncodeToString(hash[:8]) // Use first 8 bytes (16 hex chars)

	socketDir := filepath.Join(utils.RuntimeDir(), "quark", hashStr)
	if err := os.MkdirAll(socketDir, socketDirPerms); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCreateSocketDir, err)
	}

	socketPath := filepath.Join(socketDir, "docker.sock")

	// Acquire or create socket under lock (lock the directory itself)
	listener, ownsSocket, err := acquireSocket(socketPath, socketDir)
	if err != nil {
		return nil, err
	}

	client := &Client{
		sshConn:    sshConn,
		log:        log,
		socketPath: socketPath,
		ownsSocket: ownsSocket,
		listener:   listener,
		closed:     make(chan struct{}),
	}

	// Only start accept loop if we own the socket
	if ownsSocket {
		client.wg.Add(1)

		go client.acceptLoop()

		log.Debug("docker socket tunnel started", "socket", socketPath)
	} else {
		log.Debug("reusing existing docker socket tunnel", "socket", socketPath)
	}

	return client, nil
}

// acceptLoop accepts connections on the local socket and forwards them to the remote Docker socket.
func (c *Client) acceptLoop() {
	defer c.wg.Done()

	for {
		localConn, err := c.listener.Accept()
		if err != nil {
			select {
			case <-c.closed:
				return // Normal shutdown
			default:
				c.log.Error("failed to accept connection", "error", err)

				continue
			}
		}

		c.wg.Add(1)

		go c.handleConnection(localConn)
	}
}

// handleConnection forwards data between local and remote connections.
func (c *Client) handleConnection(localConn net.Conn) {
	defer c.wg.Done()
	defer localConn.Close()

	// Connect to remote Docker socket
	remoteConn, err := c.sshConn.DialUnix(remoteDockerSocket)
	if err != nil {
		c.log.Error("failed to connect to remote docker socket", "error", err)

		return
	}

	defer remoteConn.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)

	go func() {
		_, _ = io.Copy(remoteConn, localConn)
		done <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(localConn, remoteConn)
		done <- struct{}{}
	}()

	// Wait for either direction to finish
	<-done
}

// Close shuts down the socket tunnel and cleans up resources.
// If this client does not own the socket (it's reusing an existing one),
// Close is a no-op.
func (c *Client) Close() error {
	if !c.ownsSocket {
		return nil
	}

	close(c.closed)

	if err := c.listener.Close(); err != nil {
		c.log.Warn("failed to close listener", "error", err) //revive:disable-line:add-constant
	}

	c.wg.Wait()

	// Clean up socket file and directory
	socketDir := filepath.Dir(c.socketPath)
	if err := os.RemoveAll(socketDir); err != nil {
		c.log.Warn("failed to remove socket directory", "error", err, "path", socketDir)
	}

	c.log.Debug("docker socket tunnel closed")

	return nil
}

// DockerHost returns the DOCKER_HOST value to use for docker commands.
func (c *Client) DockerHost() string {
	return "unix://" + c.socketPath
}

// buildMetadata represents the metadata output from docker buildx.
type buildMetadata struct {
	//nolint:tagliatelle
	ContainerImageDigest string `json:"containerimage.digest"`
}

// BuildMultiPlatform builds for multiple platforms and pushes to registry.
// Returns the manifest digest of the pushed image.
// Multiple tags can be specified; all will be pushed in a single operation.
func (c *Client) BuildMultiPlatform(
	ctx context.Context,
	contextPath string,
	dockerfilePath string,
	platforms []string,
	tags []string,
	buildArgs map[string]string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrBuildCancelled, err)
	}

	c.log.InfoContext(ctx, "starting multi-platform build",
		"platforms", platforms,
		"tags", tags,
		"build_args", len(buildArgs))

	// Ensure builder exists (uses locking to handle concurrent builds)
	if err := c.EnsureBuilder(ctx); err != nil {
		return "", err
	}

	// Create metadata file in node's runtime directory with random suffix to avoid collisions
	metadataFile, err := c.createMetadataFile()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCreateMetadataFile, err)
	}
	defer os.Remove(metadataFile)

	// Build platforms string
	platformsStr := strings.Join(platforms, ",")

	// Build command arguments
	args := []string{
		buildxSubCmd, "build",
		"--builder", builderName,
		"--platform", platformsStr,
		"--progress", "plain",
		"--push",
		"--metadata-file", metadataFile,
		"-f", dockerfilePath,
	}

	// Add all tags
	for _, tag := range tags {
		args = append(args, "-t", tag)
	}

	// Add build args
	for key, value := range buildArgs {
		args = append(args, "--build-arg", key+"="+value)
	}

	// Add context path
	args = append(args, contextPath)

	// Execute build
	if err := c.runDocker(ctx, args...); err != nil {
		return "", fmt.Errorf("%w: %w", ErrBuildFailed, err)
	}

	// Read metadata to get digest
	digest, err := readBuildDigest(metadataFile)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrReadBuildMetadata, err)
	}

	c.log.InfoContext(ctx, "multi-platform build complete", "tags", tags, "digest", digest)

	return digest, nil
}

// createMetadataFile creates a unique file path for build metadata in the node's runtime directory.
func (c *Client) createMetadataFile() (string, error) {
	// Use the node's socket directory for metadata files
	socketDir := filepath.Dir(c.socketPath)

	// Generate random suffix to avoid collisions between concurrent builds
	var randomBytes [8]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", fmt.Errorf("%w: %w", ErrGenerateRandomBytes, err)
	}

	filename := fmt.Sprintf("build-%s.json", hex.EncodeToString(randomBytes[:]))

	return filepath.Join(socketDir, filename), nil
}

// readBuildDigest reads the image digest from the buildx metadata file.
func readBuildDigest(metadataFile string) (string, error) {
	//nolint:gosec
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrMetadataFailedReading, err)
	}

	var metadata buildMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return "", fmt.Errorf("%w: %w", ErrMetadataFailedParsing, err)
	}

	if metadata.ContainerImageDigest == "" {
		return "", ErrMetadataNoDigest
	}

	return metadata.ContainerImageDigest, nil
}

// RegistryLogin logs into a Docker registry.
func (c *Client) RegistryLogin(ctx context.Context, registry, username, password string) error {
	c.log.DebugContext(ctx, "logging into registry", "registry", registry) //revive:disable-line:add-constant

	cmd := exec.CommandContext(ctx, dockerCmd, "login", "-u", username, "--password-stdin", registry)

	cmd.Env = append(os.Environ(), "DOCKER_HOST="+c.DockerHost())
	cmd.Stdin = strings.NewReader(password)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %w (output: %s)", ErrRegistryLoginFailed, err, string(output))
	}

	c.log.InfoContext(ctx, "registry login successful", "registry", registry)

	return nil
}

// EnsureBuilder ensures the buildx builder exists.
// Uses filesystem locking to prevent concurrent creation races.
// The builder is created once and reused across builds.
func (c *Client) EnsureBuilder(ctx context.Context) error {
	lockDir := filepath.Join(utils.RuntimeDir(), "quark", "builder")
	if err := os.MkdirAll(lockDir, socketDirPerms); err != nil {
		return fmt.Errorf("%w: %w", ErrCreateBuilderLockDir, err)
	}

	var createErr error

	err := filesystem.WithLock(lockDir, func() error {
		// Check if builder already exists
		if err := c.runDockerQuiet(ctx, buildxSubCmd, "inspect", builderName); err == nil {
			// Builder exists, nothing to do
			c.log.DebugContext(
				ctx,
				"using existing buildx builder",
				"builder",
				builderName,
			) //revive:disable-line:add-constant

			return nil
		}

		// Builder doesn't exist, create it
		c.log.DebugContext(ctx, "creating buildx builder", "builder", builderName) //revive:disable-line:add-constant

		createArgs := []string{
			buildxSubCmd, "create",
			"--name", builderName,
			"--driver", "docker-container",
			"--bootstrap",
		}

		if err := c.runDocker(ctx, createArgs...); err != nil {
			createErr = fmt.Errorf("%w: %w", ErrCreateBuilder, err)

			return createErr
		}

		return nil
	})
	if err != nil {
		if createErr != nil {
			return createErr
		}

		return fmt.Errorf("%w: %w", ErrAcquireBuilderLock, err)
	}

	return nil
}

// runDocker executes a docker command with output passed through to os.Stdout/os.Stderr.
func (c *Client) runDocker(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, dockerCmd, args...)

	cmd.Env = append(os.Environ(), "DOCKER_HOST="+c.DockerHost())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %w", ErrDockerCommandFailed, err)
	}

	return nil
}

// runDockerQuiet executes a docker command without streaming output.
func (c *Client) runDockerQuiet(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, dockerCmd, args...)

	cmd.Env = append(os.Environ(), "DOCKER_HOST="+c.DockerHost())

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %w", ErrDockerCommandFailed, err)
	}

	return nil
}

// acquireSocket either creates a new socket listener or determines that an existing
// socket can be reused. This operation is protected by a file lock to prevent races.
//
// Returns:
//   - listener: the new listener if we created one, nil if reusing existing socket
//   - ownsSocket: true if we created the socket and are responsible for cleanup
//   - err: any error that occurred
func acquireSocket(socketPath, lockPath string) (net.Listener, bool, error) {
	var listener net.Listener

	var ownsSocket bool

	err := filesystem.WithLock(lockPath, func() error {
		// Check if socket file exists
		if _, statErr := os.Stat(socketPath); os.IsNotExist(statErr) {
			// Socket does not exist - create it
			var listenErr error

			listener, listenErr = net.Listen("unix", socketPath)
			if listenErr != nil {
				return fmt.Errorf("%w: %w", ErrCreateSocket, listenErr)
			}

			ownsSocket = true

			return nil
		}

		// Socket exists - check if it's alive by trying to connect
		conn, dialErr := net.DialTimeout("unix", socketPath, socketDialTimeout)
		if dialErr == nil {
			// Connection succeeded - socket is alive, reuse it
			_ = conn.Close()

			ownsSocket = false

			return nil
		}

		// Connection failed - socket is stale, remove and recreate
		if removeErr := os.Remove(socketPath); removeErr != nil {
			return fmt.Errorf("%w: %w", ErrRemoveStaleSocket, removeErr)
		}

		var listenErr error

		listener, listenErr = net.Listen("unix", socketPath)
		if listenErr != nil {
			return fmt.Errorf("%w: %w", ErrCreateSocket, listenErr)
		}

		ownsSocket = true

		return nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrAcquireSocket, err)
	}

	return listener, ownsSocket, nil
}
