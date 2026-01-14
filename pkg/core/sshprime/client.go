package sshprime

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/fault"
)

// Client represents an ssh client.
type Client struct {
	sshClient *ssh.Client
}

// NewClient returns an ssh client to the corresponding address, using the provided config.
func NewClient(addr string, config *ssh.ClientConfig) (*Client, error) {
	cli, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("%w to %s: %w", fault.ErrNetworkError, addr, err)
	}

	return &Client{
		sshClient: cli,
	}, nil
}

// SFTPClient represents an SFTP client to the node.
type SFTPClient struct {
	sftpClient *sftp.Client
}

// NewSFTPClient returns an SFTP client from a SSH client.
func NewSFTPClient(client *Client) (*SFTPClient, error) {
	sftpClient, err := sftp.NewClient(client.sshClient)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDialUnixSocket, err)
	}

	return &SFTPClient{
		sftpClient: sftpClient,
	}, nil
}

// DialUnix opens a connection to a remote Unix socket through the SSH tunnel.
// This allows local processes to communicate with remote Unix sockets (e.g., Docker daemon).
func (sc *Client) DialUnix(remotePath string) (net.Conn, error) {
	conn, err := sc.sshClient.Dial("unix", remotePath)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %w", fault.ErrSystemFailure, remotePath, err)
	}

	return conn, nil
}

// Execute runs a command on the remote host and returns stdout, stderr, and error.
func (sc *Client) Execute(command string, stdin []byte) (stdout, stderr string, err error) {
	// Prepend /usr/local/bin to PATH to include common binary locations
	// SSH non-interactive sessions have minimal PATH (/usr/bin:/bin)
	command = pathPrepend + command

	// Create a new session for this command
	session, err := sc.sshClient.NewSession()
	if err != nil {
		return "", "", wrapOpenChannelError(err)
	}

	defer func() { _ = session.Close() }()

	// Capture stdout and stderr
	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrGetPipe, err)
	}

	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrGetPipe, err)
	}

	// Get stdin pipe
	var stdinPipe io.WriteCloser
	if stdin != nil {
		stdinPipe, err = session.StdinPipe()
		if err != nil {
			return "", "", fmt.Errorf("%w: %w", ErrGetPipe, err)
		}
	}

	// Start command
	if err := session.Start(command); err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrStartCommand, err)
	}

	if stdin != nil {
		// Write data to stdin
		if _, err = stdinPipe.Write(stdin); err != nil {
			return "", "", fmt.Errorf("%w: %w", ErrWriteStdin, err)
		}

		// Close stdin to signal EOF
		if err = stdinPipe.Close(); err != nil {
			return "", "", fmt.Errorf("%w: %w", ErrCloseStdin, err)
		}
	}

	// Read output
	stdoutBytes, _ := io.ReadAll(stdoutPipe)
	stderrBytes, _ := io.ReadAll(stderrPipe)

	// Wait for command to complete
	if err = session.Wait(); err != nil {
		err = fmt.Errorf("%w: %w", ErrCommandFailed, err)
	}

	return string(stdoutBytes), string(stderrBytes), err
}

// ExecuteStreaming runs a command on the remote host and streams stdout/stderr to the provided writers.
func (sc *Client) ExecuteStreaming(command string, stdout, stderr io.Writer, stdin []byte) error {
	// Prepend /usr/local/bin to PATH to include common binary locations
	// SSH non-interactive sessions have minimal PATH (/usr/bin:/bin)
	command = pathPrepend + command

	// Create a new session for this command
	session, err := sc.sshClient.NewSession()
	if err != nil {
		return wrapOpenChannelError(err)
	}

	defer func() { _ = session.Close() }()

	// Set output writers
	session.Stdout = stdout
	session.Stderr = stderr

	// Get stdin pipe
	var stdinPipe io.WriteCloser
	if stdin != nil {
		stdinPipe, err = session.StdinPipe()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrGetPipe, err)
		}
	}

	if err := session.Start(command); err != nil {
		return fmt.Errorf("%w: %w", ErrStartCommand, err)
	}

	if stdin != nil {
		// Write data to stdin
		if _, err = stdinPipe.Write(stdin); err != nil {
			return fmt.Errorf("%w: %w", ErrWriteStdin, err)
		}

		// Close stdin to signal EOF
		if err = stdinPipe.Close(); err != nil {
			return fmt.Errorf("%w: %w", ErrCloseStdin, err)
		}
	}

	// Wait for command to complete
	if err = session.Wait(); err != nil {
		err = fmt.Errorf("%w: %w", ErrCommandFailed, err)
	}

	return err
}

// Close should be called when winding down the client.
func (sc *Client) Close() error {
	err := sc.sshClient.Close()
	if err != nil {
		err = fmt.Errorf("%w: %w", fault.ErrNetworkError, err)
	}

	sc.sshClient = nil

	return err
}

// IsAlive checks if the SSH connection is still alive by sending a keepalive request.
// Returns true if the connection responds within the timeout, false otherwise.
// If the keepalive times out, the connection is closed to prevent goroutine leaks.
func (sc *Client) IsAlive(timeout time.Duration) bool {
	if sc.sshClient == nil {
		return false
	}

	// Use a channel to implement timeout for the keepalive check
	done := make(chan bool, 1)

	go func() {
		// Send a keepalive request - this is a global request that OpenSSH servers respond to
		_, _, err := sc.sshClient.SendRequest("keepalive@openssh.com", true, nil)
		done <- err == nil
	}()

	select {
	case alive := <-done:
		return alive
	case <-time.After(timeout):
		// Connection unresponsive - close it to unblock the goroutine and mark as dead.
		// This prevents goroutine leaks when connections hang.
		_ = sc.Close()

		return false
	}
}

// Close should be called when winding down the client.
// Note: does NOT close the original ssh client.
func (sc *SFTPClient) Close() error {
	err := sc.sftpClient.Close()
	if err != nil {
		err = fmt.Errorf("%w: %w", fault.ErrNetworkError, err)
	}

	sc.sftpClient = nil

	return err
}

// UploadFile uploads a local file to the remote host using SFTP protocol.
func (sc *SFTPClient) UploadFile(localPath, remotePath string) error {
	remoteFile, err := sc.getRemoteFile(remotePath)
	if err != nil {
		return err
	}

	// Read local file
	//nolint:gosec // Path is from user config, not user input
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
	}

	defer func() { _ = localFile.Close() }()

	// Copy content from local to remote
	if _, err := io.Copy(remoteFile, localFile); err != nil {
		_ = remoteFile.Close()

		return fmt.Errorf("%w: %w", fault.ErrWriteFailure, err)
	}

	// Close remote file
	if err := remoteFile.Close(); err != nil {
		return fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
	}

	return nil
}

// UploadData uploads raw data as a file to the remote host.
// Data is uploaded directly without creating a local temporary file.
// Permissions are set to 0600 immediately after file creation to minimize the race window.
func (sc *SFTPClient) UploadData(data []byte, remotePath string) error {
	remoteFile, err := sc.getRemoteFile(remotePath)
	if err != nil {
		return err
	}

	// Write data (file now has 0600 permissions)
	if _, err := remoteFile.Write(data); err != nil {
		_ = remoteFile.Close()

		return fmt.Errorf("%w: %w", fault.ErrWriteFailure, err)
	}

	// Close remote file
	if err := remoteFile.Close(); err != nil {
		return fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
	}

	return nil
}

// IMPORTANT NOTE: this is not atomic, nor safe.
// FIXME: Upgrade to github.com/pkg/sftp/v2 when stable - v2.OpenFile(path, flags, mode)
// supports setting permissions at creation time, eliminating the TOCTOU race below.
// See: https://github.com/pkg/sftp/issues/335
func (sc *SFTPClient) getRemoteFile(remotePath string) (*sftp.File, error) {
	// Create remote file using SFTP (truncate if exists)
	remoteFile, err := sc.sftpClient.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
	}

	// SECURITY: Set restrictive permissions IMMEDIATELY after creation, BEFORE writing data.
	// pkg/sftp v1's OpenFile doesn't support setting mode at creation time, so we minimize
	// the race window by chmod'ing before any sensitive data is written.
	if err := sc.sftpClient.Chmod(remotePath, filesystem.FilePermissionsPrivate); err != nil {
		_ = remoteFile.Close()

		return nil, fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
	}

	return remoteFile, nil
}

// wrapOpenChannelError wraps an ssh.OpenChannelError with a typed error based on RejectionReason.
// Returns the original error wrapped if it's not an OpenChannelError.
func wrapOpenChannelError(err error) error {
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) {
		return err
	}

	switch openErr.Reason {
	case ssh.Prohibited:
		return fmt.Errorf("%w: %w", ErrConnectionProhibited, err)
	case ssh.ConnectionFailed:
		// ConnectionFailed typically indicates MaxSessions exceeded
		return fmt.Errorf("%w: %w", ErrSessionLimitExceeded, err)
	case ssh.ResourceShortage:
		return fmt.Errorf("%w: %w", ErrResourceShortage, err)
	case ssh.UnknownChannelType:
		return fmt.Errorf("%w (unknown channel type): %w", ErrChannelOpen, err)
	default:
		return fmt.Errorf("%w: %w", ErrChannelOpen, err)
	}
}
