// Package buildkit provides buildkit client operations via SSH.
package buildkit

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/carapace-sh/carapace-shlex"
	"github.com/rs/zerolog"

	"github.com/farcloser/quark/ssh"
)

const (
	// builderName is the name of the buildx builder instance used for multi-platform builds.
	builderName = "quark-builder"
)

// Client wraps buildkit operations over SSH.
type Client struct {
	sshConn ssh.Connection
	log     zerolog.Logger
}

// NewClient creates a new buildkit client using SSH.
func NewClient(sshConn ssh.Connection, log zerolog.Logger) *Client {
	return &Client{
		sshConn: sshConn,
		log:     log,
	}
}

// Build executes a build on the remote buildkit node.
// Returns the image tag that was built (digest retrieval requires registry operations).
func (bkclient *Client) Build(
	ctx context.Context,
	contextPath string,
	dockerfilePath string,
	platform string,
) (string, error) {
	// Check context for cancellation
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("build cancelled: %w", err)
	}

	bkclient.log.Info().
		Str("context", contextPath).
		Str("dockerfile", dockerfilePath).
		Str("platform", platform).
		Msg("starting buildkit build")

	// Connect to buildkit daemon via SSH
	// Note: buildkit client library doesn't support SSH directly,
	// so we need to tunnel through SSH or use buildkit's SSH support

	// For now, we'll use docker buildx over SSH as a simpler approach
	// This requires buildkit to be running on the remote host

	buildCmd := fmt.Sprintf(
		"docker buildx build --platform %s --load -f %s %s",
		shlex.Join([]string{platform}),
		shlex.Join([]string{dockerfilePath}),
		shlex.Join([]string{contextPath}),
	)

	stdout, stderr, err := bkclient.sshConn.Execute(buildCmd)
	if err != nil {
		bkclient.log.Error().
			Str("stdout", stdout).
			Str("stderr", stderr).
			Err(err).
			Msg("build failed")

		return "", fmt.Errorf("build failed: %w", err)
	}

	bkclient.log.Info().Msg("build complete")

	return stdout, nil
}

// ensureBuilder ensures a docker-container builder exists for multi-platform builds.
func (bkclient *Client) ensureBuilder() error {
	// Create builder if it doesn't exist (idempotent - succeeds if already exists)
	createCmd := fmt.Sprintf(
		"docker buildx create --name %s --driver docker-container --bootstrap --use 2>/dev/null || true",
		shlex.Join([]string{builderName}),
	)

	_, _, err := bkclient.sshConn.Execute(createCmd)
	if err != nil {
		return fmt.Errorf("failed to ensure builder exists: %w", err)
	}

	return nil
}

// BuildMultiPlatform builds for multiple platforms and creates a manifest list.
// Returns the tag that was built (digest retrieval requires registry operations).
func (bkclient *Client) BuildMultiPlatform(
	ctx context.Context,
	contextPath string,
	dockerfilePath string,
	platforms []string,
	tag string,
) (string, error) {
	// Check context for cancellation
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("build cancelled: %w", err)
	}

	bkclient.log.Info().
		Strs("platforms", platforms).
		Str("tag", tag).
		Msg("starting multi-platform build")

	// Ensure builder exists
	if err := bkclient.ensureBuilder(); err != nil {
		return "", err
	}

	// Build command with multiple platforms
	platformsStr := ""

	for idx, platform := range platforms {
		if idx > 0 {
			platformsStr += ","
		}

		platformsStr += platform
	}

	buildCmd := fmt.Sprintf(
		"docker buildx build --builder %s --platform %s --push -t %s -f %s %s",
		shlex.Join([]string{builderName}),
		shlex.Join([]string{platformsStr}),
		shlex.Join([]string{tag}),
		shlex.Join([]string{dockerfilePath}),
		shlex.Join([]string{contextPath}),
	)

	// Stream build output to logger
	stdoutWriter := &logWriter{log: bkclient.log.With().Str("stream", "stdout").Logger()}
	stderrWriter := &logWriter{log: bkclient.log.With().Str("stream", "stderr").Logger()}

	err := bkclient.sshConn.ExecuteStreaming(buildCmd, stdoutWriter, stderrWriter)
	if err != nil {
		bkclient.log.Error().
			Err(err).
			Msg("multi-platform build failed")

		return "", fmt.Errorf("multi-platform build failed: %w", err)
	}

	bkclient.log.Info().
		Str("tag", tag).
		Msg("multi-platform build complete")

	return tag, nil
}

// UploadContext uploads the build context to the remote host.
func (bkclient *Client) UploadContext(localPath, remotePath string) error {
	bkclient.log.Debug().
		Str("local", localPath).
		Str("remote", remotePath).
		Msg("uploading build context")

	// Create remote directory
	mkdirCmd := "mkdir -p " + shlex.Join([]string{remotePath})
	if _, _, err := bkclient.sshConn.Execute(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create remote directory: %w", err)
	}

	// Walk local directory and upload files
	return uploadDirectory(bkclient.sshConn, localPath, remotePath)
}

func uploadDirectory(sshConn ssh.Connection, localDir, remoteDir string) error {
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return fmt.Errorf("failed to read local directory: %w", err)
	}

	for _, entry := range entries {
		localPath := fmt.Sprintf("%s/%s", localDir, entry.Name())
		remotePath := fmt.Sprintf("%s/%s", remoteDir, entry.Name())

		if entry.IsDir() {
			// Recursively upload directory
			if err := uploadDirectory(sshConn, localPath, remotePath); err != nil {
				return err
			}
		} else {
			// Upload file
			if err := sshConn.UploadFile(localPath, remotePath); err != nil {
				return fmt.Errorf("failed to upload file %s: %w", localPath, err)
			}
		}
	}

	return nil
}

// GetDigest retrieves the digest of a built image.
func (bkclient *Client) GetDigest(tag string) (string, error) {
	inspectCmd := "docker inspect --format='{{.Id}}' " + shlex.Join([]string{tag})

	stdout, _, err := bkclient.sshConn.Execute(inspectCmd)
	if err != nil {
		return "", fmt.Errorf("failed to get image digest: %w", err)
	}

	return stdout, nil
}

// logWriter writes to zerolog, splitting output into lines.
var _ io.Writer = (*logWriter)(nil)

type logWriter struct {
	log    zerolog.Logger
	buffer []byte
}

func (writer *logWriter) Write(bytes []byte) (int, error) {
	// Append to buffer
	writer.buffer = append(writer.buffer, bytes...)

	// Process complete lines
	for {
		// Find newline
		idx := -1

		for i, b := range writer.buffer {
			if b == '\n' {
				idx = i

				break
			}
		}

		// No complete line found
		if idx == -1 {
			break
		}

		// Extract line (without newline)
		line := string(writer.buffer[:idx])
		writer.buffer = writer.buffer[idx+1:]

		// Log line if not empty
		if line != "" {
			writer.log.Info().Msg(line)
		}
	}

	return len(bytes), nil
}

// Note: This is a simplified implementation using docker buildx over SSH.
// A full implementation would use the buildkit client library directly with SSH tunneling.
// The buildkit client library requires more complex setup with session management.
// This approach is more practical and works with existing buildkit/buildx setups.

// var _ client.Client // Ensure buildkit client is imported for future use
