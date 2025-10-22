# Package buildkit

## Purpose

Provides remote BuildKit operations over SSH for building multi-platform container images on distributed build nodes.

## Functionality

- **Remote builds** - Execute Docker/BuildKit builds on remote nodes via SSH
- **Multi-platform support** - Build images for different architectures (amd64, arm64)
- **Context upload** - Transfer build context from local machine to remote builder
- **Digest extraction** - Retrieve image digests after successful builds

## Public API

```go
type Client struct { ... }
func NewClient(sshConn ssh.Connection, log zerolog.Logger) *Client

// Build operations
func (c *Client) Build(ctx context.Context, contextPath, dockerfilePath, platform string) (string, error)
func (c *Client) BuildMultiPlatform(ctx context.Context, contextPath, dockerfilePath, tag string, platforms []string) error
func (c *Client) UploadContext(localPath, remotePath string) error
func (c *Client) GetDigest(tag string) (string, error)
```

## Design

- **SSH-based communication**: Leverages hadron's SSH connection pooling for remote command execution
- **Docker buildx**: Uses `docker buildx build` commands for actual build operations
- **Remote execution**: All build operations happen on remote nodes, not locally
- **Platform-specific builds**: Each platform (amd64, arm64) built on dedicated hardware nodes

## Dependencies

- External: `moby/buildkit/client` (for BuildKit types/interfaces)
- Internal: `hadron/sdk/ssh` for SSH connection management

## Notes

- Requires BuildKit/Docker to be installed and configured on remote nodes
- Uses `--load` flag to import built images into local Docker daemon on remote host
- Multi-platform builds push each platform image with platform suffix (e.g., `image:tag-amd64`)
