package docker

import (
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/pkg/dev/ssh"
	"github.com/farcloser/quark/pkg/dev/tunnel"
)

const (
	// remoteDockerSocket is the path to the Docker socket on the remote host.
	remoteDockerSocket = "/var/run/docker.sock"
)

// ManagedSocket represents a tunneled Docker socket.
// Safe for concurrent access within the same process.
type ManagedSocket struct {
	tunnel *tunnel.Tunnel
}

// AcquireSocket gets or creates a managed docker socket for the given SSH connection.
// Multiple callers within the same process will share the same socket.
// Call Release() when done to allow cleanup when all holders release.
func AcquireSocket(conn ssh.Connection, log *slog.Logger) (*ManagedSocket, error) {
	tunnel, err := tunnel.Acquire(conn, remoteDockerSocket, log)
	if err != nil {
		return nil, fmt.Errorf("docker socket: %w", err)
	}

	return &ManagedSocket{tunnel: tunnel}, nil
}

// Release releases this holder's claim on the socket.
// When the last holder releases, the socket is cleaned up.
func (s *ManagedSocket) Release() {
	s.tunnel.Release()
}

// SocketPath returns the local socket path.
func (s *ManagedSocket) SocketPath() string {
	return s.tunnel.LocalPath()
}

// DockerHost returns the DOCKER_HOST value for this socket.
func (s *ManagedSocket) DockerHost() string {
	return "unix://" + s.tunnel.LocalPath()
}
