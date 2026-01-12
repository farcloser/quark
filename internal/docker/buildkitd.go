package docker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

const (
	// BuildkitdContainerName is the name of the buildkitd container.
	BuildkitdContainerName = "quark-buildkitd"

	// BuildkitdImage is the Docker image to use for buildkitd.
	BuildkitdImage = "moby/buildkit:v0.26.2"

	// dockerCmd is the docker command name.
	dockerCmd = "docker"
)

// BuildkitdManager handles buildkitd container lifecycle on remote hosts.
type BuildkitdManager struct {
	log        *slog.Logger
	dockerHost string
}

// NewBuildkitdManager creates a new buildkitd manager.
// dockerHost should be the DOCKER_HOST value (e.g., "unix:///path/to/docker.sock").
func NewBuildkitdManager(dockerHost string, log *slog.Logger) *BuildkitdManager {
	return &BuildkitdManager{
		log:        log.With("component", "buildkitd"),
		dockerHost: dockerHost,
	}
}

// EnsureDaemon ensures the buildkitd container is running on the remote host.
// This is race-tolerant: if two processes try to start the container simultaneously,
// the second will detect the running container after the initial start fails.
func (bm *BuildkitdManager) EnsureDaemon(ctx context.Context) error {
	// First, check if the container is already running
	if bm.isRunning(ctx) {
		bm.log.DebugContext(ctx, "buildkitd container already running")

		return nil
	}

	bm.log.InfoContext(ctx, "starting buildkitd container")

	// Try to start the container
	if err := bm.startContainer(ctx); err != nil {
		// Start failed - this might be a race condition where another process
		// started the container. Check again if it's running.
		if bm.isRunning(ctx) {
			bm.log.DebugContext(ctx, "buildkitd container started by another process")

			return nil
		}

		// Still not running - this is a real failure
		return fmt.Errorf("%w: %w", ErrBuildkitdStart, err)
	}

	bm.log.InfoContext(ctx, "buildkitd container started")

	return nil
}

// isRunning checks if the buildkitd container is running.
func (bm *BuildkitdManager) isRunning(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, dockerCmd,
		"inspect", "-f", "{{.State.Running}}", BuildkitdContainerName)
	cmd.Env = bm.dockerEnv()

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(output)) == "true"
}

// startContainer starts the buildkitd container.
func (bm *BuildkitdManager) startContainer(ctx context.Context) error {
	// Remove any existing stopped container first
	_ = bm.removeContainer(ctx)

	// No socket mount needed - buildctl uses docker-container:// scheme
	// which communicates with buildkitd via docker exec.
	args := []string{
		"run",
		"--detach",
		"--privileged",
		"--name", BuildkitdContainerName,
		"--restart", "unless-stopped",
		BuildkitdImage,
	}

	bm.log.DebugContext(ctx, "starting container", "args", args)

	cmd := exec.CommandContext(ctx, dockerCmd, args...)
	cmd.Env = bm.dockerEnv()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker run failed: %w\n%s", err, output)
	}

	return nil
}

// removeContainer removes the buildkitd container if it exists.
func (bm *BuildkitdManager) removeContainer(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, dockerCmd, "rm", "-f", BuildkitdContainerName)
	cmd.Env = bm.dockerEnv()

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %w", ErrDockerCommandFailed, err)
	}

	return nil
}

// dockerEnv returns the environment variables for docker commands.
func (bm *BuildkitdManager) dockerEnv() []string {
	env := os.Environ()

	if bm.dockerHost != "" {
		env = append(env, "DOCKER_HOST="+bm.dockerHost)
	}

	return env
}

// BuildctlAddr returns the buildctl --addr value for connecting to this buildkitd.
// Uses the docker-container:// scheme which works via docker exec.
func BuildctlAddr() string {
	return "docker-container://" + BuildkitdContainerName
}
