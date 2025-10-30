// Package ssh provides SSH client and connection pool utilities.
package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kevinburke/ssh_config"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/farcloser/quark/filesystem"
)

var (
	errNotConnected        = errors.New("not connected")
	errHostKeyMismatch     = errors.New("host key verification failed: key mismatch (possible MITM attack)")
	errHostNotInKnownHosts = errors.New("host key verification failed: host not found in known_hosts")
	errNoSSHAgent          = errors.New("SSH agent not available: ensure SSH_AUTH_SOCK is set and ssh-agent is running")
	errInvalidPort         = errors.New("invalid port in SSH config")
	errPassphraseKey       = errors.New("SSH key is passphrase-protected (use unencrypted key or SSH agent)")
	errIdentityKeyNotFound = errors.New("identity file key not found in SSH agent")
)

const (
	defaultSSHPort = 22
)

// Connection represents an active SSH connection.
// All methods are safe for use within the context managed by Pool.
type Connection interface {
	Execute(command string) (stdout, stderr string, err error)
	ExecuteStreaming(command string, stdout, stderr io.Writer) error
	UploadFile(localPath, remotePath string) error
	UploadData(data []byte, remotePath string) error
}

// client represents an SSH client with connection pooling.
// This type is intentionally unexported - use Pool.GetClient() to obtain connections.
type client struct {
	endpoint           string
	hostname           string
	user               string
	port               int
	sshClient          *ssh.Client
	sftpClient         *sftp.Client
	agentConn          net.Conn
	sshFingerprint     string
	sshKeyContent      string
	identityFilePubKey ssh.PublicKey // Public key from IdentityFile (for agent filtering)
	mu                 sync.Mutex
}

// newClient creates a new SSH client for the given endpoint.
// The endpoint can be an IP address, hostname, or SSH config alias.
// Connection parameters (User, Port, Hostname) are resolved from ~/.ssh/config.
// If fingerprint is provided, it will be used for host key verification instead of ~/.ssh/known_hosts.
// If keyContent is provided, it will be used for authentication instead of SSH agent.
func newClient(endpoint, fingerprint, keyContent string) *client {
	return &client{
		endpoint:       endpoint,
		sshFingerprint: fingerprint,
		sshKeyContent:  keyContent,
	}
}

// connect establishes an SSH connection to the remote host using SSH key or agent.
// Connection parameters are resolved from ~/.ssh/config based on the endpoint.
func (c *client) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sshClient != nil {
		return nil // already connected
	}

	// Resolve connection parameters from SSH config
	if err := c.resolveConfig(); err != nil {
		return fmt.Errorf("failed to resolve SSH config: %w", err)
	}

	// Get auth method (SSH key or agent)
	authMethod, err := c.getAuthMethod()
	if err != nil {
		return err
	}

	// Load host key callback
	hostKeyCallback, err := c.loadHostKeyCallback()
	if err != nil {
		return fmt.Errorf("failed to load host key callback: %w", err)
	}

	// Create SSH client config
	config := &ssh.ClientConfig{
		User: c.user,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: hostKeyCallback,
		// Only accept Ed25519 host keys (most secure, modern standard)
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoED25519,
		},
		// Timeout prevents indefinite hangs on unreachable/slow hosts
		Timeout: 30 * time.Second, //revive:disable:add-constant
	}

	// Connect to remote host
	addr := fmt.Sprintf("%s:%d", c.hostname, c.port)

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	c.sshClient = client

	// Initialize SFTP client for file operations
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		_ = client.Close()
		c.sshClient = nil

		return fmt.Errorf("failed to initialize SFTP client: %w", err)
	}

	c.sftpClient = sftpClient

	return nil
}

// resolveConfig resolves SSH connection parameters from ~/.ssh/config.
func (c *client) resolveConfig() error {
	endpointUser, endpointHost := c.parseEndpoint()
	c.user = c.resolveUser(endpointUser)
	c.hostname = c.resolveHostname(endpointHost)

	if err := c.resolvePort(); err != nil {
		return err
	}

	return c.resolveIdentityFile()
}

// parseEndpoint extracts user and hostname from endpoint (user@host format).
func (c *client) parseEndpoint() (user, host string) {
	if u, h, found := strings.Cut(c.endpoint, "@"); found {
		return u, h
	}

	return "", c.endpoint
}

// resolveUser determines the SSH user from endpoint, SSH config, or current user.
func (c *client) resolveUser(endpointUser string) string {
	if endpointUser != "" {
		return endpointUser
	}

	if user := ssh_config.Get(c.endpoint, "User"); user != "" {
		return user
	}

	return c.getCurrentUser()
}

// getCurrentUser returns the current system user or "root" as fallback.
func (*client) getCurrentUser() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}

	if user := os.Getenv("LOGNAME"); user != "" {
		return user
	}

	return "root"
}

// resolvePort determines the SSH port from SSH config or uses default.
func (c *client) resolvePort() error {
	portStr := ssh_config.Get(c.endpoint, "Port")
	if portStr == "" {
		c.port = defaultSSHPort

		return nil
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("%w: %s", errInvalidPort, portStr)
	}

	c.port = port

	return nil
}

// resolveHostname determines the SSH hostname from SSH config or uses endpoint.
func (c *client) resolveHostname(endpointHost string) string {
	if hostname := ssh_config.Get(c.endpoint, "Hostname"); hostname != "" {
		return hostname
	}

	return endpointHost
}

// resolveIdentityFile loads SSH key from IdentityFile if IdentitiesOnly is set.
func (c *client) resolveIdentityFile() error {
	if c.sshKeyContent != "" {
		return nil // Explicit key already provided
	}

	if ssh_config.Get(c.endpoint, "IdentitiesOnly") != "yes" {
		return nil // IdentitiesOnly not enabled
	}

	identityFiles := ssh_config.GetAll(c.endpoint, "IdentityFile")
	if len(identityFiles) == 0 {
		return nil
	}

	// Use the last (most specific) IdentityFile
	identityFile := identityFiles[len(identityFiles)-1]
	if identityFile == "" {
		return nil
	}

	return c.loadIdentityFile(identityFile)
}

// loadIdentityFile reads and parses an SSH identity file.
func (c *client) loadIdentityFile(identityFile string) error {
	identityFile = c.expandHomedir(identityFile)

	// #nosec G304 -- identityFile comes from SSH config, reading identity files is required functionality
	keyBytes, err := os.ReadFile(identityFile)
	if err != nil {
		return fmt.Errorf("failed to read identity file %s: %w", identityFile, err)
	}

	return c.parseIdentityKey(keyBytes, identityFile)
}

// expandHomedir expands ~ prefix to user's home directory.
func (*client) expandHomedir(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return path // Fallback to original path
	}

	return filepath.Join(home, path[2:])
}

// parseIdentityKey parses SSH key bytes and handles passphrase-protected keys.
func (c *client) parseIdentityKey(keyBytes []byte, identityFile string) error {
	_, err := ssh.ParsePrivateKey(keyBytes)
	if err == nil {
		// Key is not passphrase-protected - use it directly
		c.sshKeyContent = string(keyBytes)

		return nil
	}

	// Check if this is a passphrase-protected key
	var passphraseErr *ssh.PassphraseMissingError
	if !errors.As(err, &passphraseErr) {
		return fmt.Errorf("failed to parse identity file %s: %w", identityFile, err)
	}

	// Key is passphrase-protected - extract public key and use agent
	// The public key will be used to filter agent keys (IdentitiesOnly behavior)
	c.identityFilePubKey = passphraseErr.PublicKey

	return nil
}

// close closes the SSH connection.
func (c *client) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close SFTP client first
	if c.sftpClient != nil {
		_ = c.sftpClient.Close()
		c.sftpClient = nil
	}

	// Close SSH agent connection to prevent file descriptor leak
	// Must be done before checking sshClient, as agentConn may be set even if sshClient is nil
	if c.agentConn != nil {
		_ = c.agentConn.Close()
		c.agentConn = nil
	}

	// Then close SSH connection
	if c.sshClient == nil {
		return nil
	}

	err := c.sshClient.Close()
	c.sshClient = nil

	if err != nil {
		return fmt.Errorf("%w: %w", ErrConnectionClose, err)
	}

	return nil
}

// Execute runs a command on the remote host and returns stdout, stderr, and error.
func (c *client) Execute(command string) (stdout, stderr string, err error) {
	if c.sshClient == nil {
		return "", "", errNotConnected
	}

	// Create a new session for this command
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create session: %w", err)
	}

	defer func() { _ = session.Close() }()

	// Capture stdout and stderr
	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return "", "", fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return "", "", fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	// Prepend /usr/local/bin to PATH to include common binary locations
	// SSH non-interactive sessions have minimal PATH (/usr/bin:/bin)
	command = "PATH=/usr/local/bin:$PATH " + command

	// Start command
	if err := session.Start(command); err != nil {
		return "", "", fmt.Errorf("failed to start command: %w", err)
	}

	// Read output
	stdoutBytes, _ := io.ReadAll(stdoutPipe)
	stderrBytes, _ := io.ReadAll(stderrPipe)

	// Wait for command to complete
	if err := session.Wait(); err != nil {
		return string(stdoutBytes), string(stderrBytes), fmt.Errorf("command failed: %w", err)
	}

	return string(stdoutBytes), string(stderrBytes), nil
}

// ExecuteStreaming runs a command on the remote host and streams stdout/stderr to the provided writers.
func (c *client) ExecuteStreaming(command string, stdout, stderr io.Writer) error {
	if c.sshClient == nil {
		return errNotConnected
	}

	// Create a new session for this command
	session, err := c.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	defer func() { _ = session.Close() }()

	// Set output writers
	session.Stdout = stdout
	session.Stderr = stderr

	// Prepend /usr/local/bin to PATH to include common binary locations
	// SSH non-interactive sessions have minimal PATH (/usr/bin:/bin)
	command = "PATH=/usr/local/bin:$PATH " + command

	// Run command (blocks until completion)
	if err := session.Run(command); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

// getAuthMethod returns an SSH auth method, preferring SSH key over agent.
// If SSH key content is provided, it will be parsed and used for authentication.
// Otherwise, falls back to SSH agent authentication.
func (c *client) getAuthMethod() (ssh.AuthMethod, error) {
	// If SSH key is provided, use it
	if c.sshKeyContent != "" {
		signer, err := c.parseSSHKey()
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH key: %w", err)
		}

		return ssh.PublicKeys(signer), nil
	}

	// Otherwise use SSH agent
	return c.getSSHAgentAuth()
}

// parseSSHKey parses an SSH private key from the provided content.
// Supports both encrypted (passphrase-protected) and unencrypted keys.
// For encrypted keys, this will return an error - passphrase support requires user interaction.
func (c *client) parseSSHKey() (ssh.Signer, error) {
	// Parse the private key
	signer, err := ssh.ParsePrivateKey([]byte(c.sshKeyContent))
	if err != nil {
		// Check if this is a passphrase-protected key
		var passphraseErr *ssh.PassphraseMissingError
		if errors.As(err, &passphraseErr) {
			return nil, errPassphraseKey
		}

		return nil, fmt.Errorf("invalid SSH key format: %w", err)
	}

	return signer, nil
}

// getSSHAgentAuth returns an SSH auth method using the SSH agent.
// If identityFilePubKey is set, it filters agent keys to only use the matching key (IdentitiesOnly behavior).
func (c *client) getSSHAgentAuth() (ssh.AuthMethod, error) {
	// Get SSH_AUTH_SOCK environment variable
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, errNoSSHAgent
	}

	// Connect to SSH agent
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to connect to agent socket: %w", errNoSSHAgent, err)
	}

	// Store connection for cleanup in Close()
	c.agentConn = conn

	// Create agent client
	agentClient := agent.NewClient(conn)

	// If IdentityFile public key is specified, filter agent keys to only use that key
	if c.identityFilePubKey != nil {
		return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			allSigners, err := agentClient.Signers()
			if err != nil {
				return nil, fmt.Errorf("failed to get signers from SSH agent: %w", err)
			}

			// Filter signers to only include the one matching IdentityFile
			for _, signer := range allSigners {
				if ssh.FingerprintSHA256(signer.PublicKey()) == ssh.FingerprintSHA256(c.identityFilePubKey) {
					return []ssh.Signer{signer}, nil
				}
			}

			return nil, errIdentityKeyNotFound
		}), nil
	}

	// Return auth method that uses all agent keys
	return ssh.PublicKeysCallback(agentClient.Signers), nil
}

// loadHostKeyCallback loads the host key callback for SSH host verification.
// If a fingerprint is configured, it will be used for verification.
// Otherwise, it uses the standard ~/.ssh/known_hosts file for verification.
func (c *client) loadHostKeyCallback() (ssh.HostKeyCallback, error) {
	// If fingerprint is provided, use fingerprint verification
	if c.sshFingerprint != "" {
		return c.fingerprintCallback(), nil
	}

	// Otherwise use known_hosts verification
	return c.knownHostsCallback()
}

// fingerprintCallback creates a host key callback that verifies against the configured fingerprint.
func (c *client) fingerprintCallback() ssh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		// Calculate the fingerprint of the received key
		actualFingerprint := ssh.FingerprintSHA256(key)

		// Compare with expected fingerprint
		if actualFingerprint != c.sshFingerprint {
			return fmt.Errorf(
				"%w: expected %s, got %s for %s",
				errHostKeyMismatch,
				c.sshFingerprint,
				actualFingerprint,
				hostname,
			)
		}

		return nil
	}
}

// knownHostsCallback creates a host key callback that verifies against ~/.ssh/known_hosts.
func (c *client) knownHostsCallback() (ssh.HostKeyCallback, error) {
	// Get home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	// Standard known_hosts path
	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")

	// Check if known_hosts exists
	if _, err := os.Stat(knownHostsPath); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to check known_hosts: %w", err)
		}

		// If known_hosts doesn't exist, create it with proper permissions
		sshDir := filepath.Join(home, ".ssh")
		if err := os.MkdirAll(sshDir, filesystem.DirPermissionsPrivate); err != nil {
			return nil, fmt.Errorf("failed to create .ssh directory: %w", err)
		}

		// Create empty known_hosts file
		//nolint:gosec
		file, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_WRONLY, filesystem.FilePermissionsPrivate)
		if err != nil {
			return nil, fmt.Errorf("failed to create known_hosts: %w", err)
		}

		_ = file.Close()
	}

	// Load known_hosts
	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load known_hosts: %w", err)
	}

	// Wrap the callback to provide better error messages
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := hostKeyCallback(hostname, remote, key)
		if err != nil {
			// Check if this is a key mismatch error
			var keyErr *knownhosts.KeyError
			if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
				return fmt.Errorf(
					"%w for %s. If you trust this host, remove the old key from %s and retry",
					errHostKeyMismatch,
					hostname,
					knownHostsPath,
				)
			}

			// Check if this is an unknown host error
			if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
				return fmt.Errorf(
					"%w: %s. To add this host, run: ssh-keyscan -H %s >> %s",
					errHostNotInKnownHosts,
					hostname,
					c.hostname,
					knownHostsPath,
				)
			}

			return fmt.Errorf("host key verification failed: %w", err)
		}

		return nil
	}, nil
}

// String returns a string representation of the client.
func (c *client) String() string {
	if c.hostname != "" {
		return fmt.Sprintf("%s@%s:%d", c.user, c.hostname, c.port)
	}

	return c.endpoint
}

// UploadFile uploads a local file to the remote host using SFTP protocol.
func (c *client) UploadFile(localPath, remotePath string) error {
	if c.sshClient == nil {
		return errNotConnected
	}

	// Read local file
	//nolint:gosec // Path is from user config, not user input
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}

	defer func() { _ = localFile.Close() }()

	// Create remote file using SFTP
	remoteFile, err := c.sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}

	// Copy content from local to remote
	if _, err := io.Copy(remoteFile, localFile); err != nil {
		_ = remoteFile.Close()

		return fmt.Errorf("failed to write file content: %w", err)
	}

	// Close remote file
	if err := remoteFile.Close(); err != nil {
		return fmt.Errorf("failed to close remote file: %w", err)
	}

	// Set file permissions to 0600 (owner read/write only)
	if err := c.sftpClient.Chmod(remotePath, filesystem.FilePermissionsPrivate); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	return nil
}

// UploadData uploads raw data as a file to the remote host.
// Data is uploaded directly without creating a local temporary file.
func (c *client) UploadData(data []byte, remotePath string) error {
	if c.sshClient == nil {
		return errNotConnected
	}

	// Create remote file using SFTP (truncate if exists)
	remoteFile, err := c.sftpClient.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}

	// Write data
	if _, err := remoteFile.Write(data); err != nil {
		_ = remoteFile.Close()

		return fmt.Errorf("failed to write file content: %w", err)
	}

	// Close remote file
	if err := remoteFile.Close(); err != nil {
		return fmt.Errorf("failed to close remote file: %w", err)
	}

	// Set file permissions to 0600 (owner read/write only)
	if err := c.sftpClient.Chmod(remotePath, filesystem.FilePermissionsPrivate); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	return nil
}
