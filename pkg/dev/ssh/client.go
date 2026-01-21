package ssh

import (
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/core/sshprime"
)

// Connection represents an active SSH connection.
// All methods are safe for use within the context managed by Pool.
type Connection interface {
	// Execute a command on the remote endpoint.
	Execute(command string, stdin []byte) (stdout, stderr string, err error)
	// ExecuteStreaming a command on the remote endpoint with IO streaming.
	ExecuteStreaming(command string, stdout, stderr io.Writer, stdin []byte) error
	// UploadFile uploads a file to the remote.
	UploadFile(localPath, remotePath string) error
	// UploadData uploads raw data to the remote.
	UploadData(data []byte, remotePath string) error
	// DialUnix opens a unix socket tunnelled through the ssh connection.
	DialUnix(remotePath string) (net.Conn, error)
	// Endpoint returns a unique identifier for the addr:port.
	Endpoint() string
}

// client represents an SSH client with connection pooling.
// This type is intentionally unexported - use Pool.GetClient() to obtain connections, which does mutex
// for concurrency safety.
type client struct {
	*sshprime.Client
	*sshprime.SFTPClient

	endpoint *sshprime.Endpoint
}

// newClient creates a new SSH client for the given endpoint.
func newClient(endpoint *sshprime.Endpoint) *client {
	return &client{
		endpoint: endpoint,
	}
}

func (c *client) Endpoint() string {
	return fmt.Sprintf("%s:%d", c.endpoint.Host, c.endpoint.Port)
}

// connect establishes an SSH connection to the remote host using SSH key or agent.
// Connection parameters are resolved from ~/.ssh/config based on the endpoint.
func (c *client) connect(config *ssh.ClientConfig) error {
	addr := fmt.Sprintf("%s:%d", c.endpoint.Host, c.endpoint.Port)

	cli, err := sshprime.NewClient(addr, config)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedToConnect, err)
	}

	c.Client = cli

	// Initialize SFTP client for file operations
	sftpClient, err := sshprime.NewSFTPClient(cli)
	if err != nil {
		_ = cli.Close()

		return fmt.Errorf("%w: %w", ErrFailedToConnect, err)
	}

	c.SFTPClient = sftpClient

	return nil
}

// close closes the SSH connection.
func (c *client) close() error {
	// Close SFTP client first
	_ = c.SFTPClient.Close()
	c.SFTPClient = nil

	err := c.Client.Close()
	c.Client = nil

	if err != nil {
		//nolint:wrapcheck
		return err
	}

	return nil
}
