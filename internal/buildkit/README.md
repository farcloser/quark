# Package buildkit

## Purpose

Provides remote BuildKit operations over SSH for building multi-platform container images on distributed build nodes.

## Functionality

- **Remote builds** - Execute Docker/BuildKit builds on remote nodes via SSH tunnel
- **Multi-platform support** - Build images for different architectures (amd64, arm64)
- **Socket forwarding** - Creates local Unix socket that forwards to remote Docker daemon
- **Digest extraction** - Retrieve image digests after successful builds

## Public API

```go
type Client struct { ... }
func NewClient(sshConn ssh.Connection, nodeID string, log *slog.Logger) (*Client, error)

// Build operations
func (c *Client) BuildMultiPlatform(ctx context.Context, contextPath, dockerfilePath string, platforms, tags []string, buildArgs map[string]string) (string, error)

// Connection management
func (c *Client) DockerHost() string  // Returns unix:// path for DOCKER_HOST
func (c *Client) Close() error        // Closes SSH tunnel and cleans up
```

## Design

- **SSH-based communication**: Uses SSH connection for remote Docker socket forwarding
- **Local socket proxy**: Creates a local Unix socket that tunnels to remote Docker daemon
- **Docker buildx**: Uses `docker buildx build` with `--push` for multi-platform builds
- **Stable socket paths**: Socket paths based on hashed node ID for predictable locations
- **Color customization**: Sets BUILDKIT_COLORS environment for consistent output

## Multi-Platform Build Flow

1. Ensure quark-builder (docker-container driver) exists
2. Forward local socket to remote Docker daemon via SSH
3. Execute `docker buildx build` with multiple `--platform` flags
4. Push manifest list directly to registry
5. Extract and return manifest digest

## Dependencies

- External: Docker with BuildKit support on remote nodes
- Internal: `dev/ssh` for SSH connection management, `internal2/utils` for runtime directory

## Notes

- Requires Docker with buildx plugin installed on remote nodes
- Multi-platform builds require a docker-container builder (automatically created as "quark-builder")
- Socket files stored in `RuntimeDir()/buildkit/` with stable hashed names
