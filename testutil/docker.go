package testutil

import (
	"context"
	"os/exec"
)

// DockerAvailable returns true if Docker is available and responsive.
func DockerAvailable(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "docker", "info")

	return cmd.Run() == nil
}
