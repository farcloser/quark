package ssh

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Exported errors for consumer type checking.
var (
	// ErrConnectionClose indicates failure closing SSH connection.
	ErrConnectionClose = errors.New("failed to close SSH connection")

	// ErrSessionLimitExceeded indicates the server's MaxSessions limit was reached.
	// This typically means too many concurrent sessions on a single SSH connection.
	ErrSessionLimitExceeded = errors.New("SSH session limit exceeded (server MaxSessions reached)")

	// ErrConnectionProhibited indicates the server rejected the connection request.
	ErrConnectionProhibited = errors.New("SSH connection prohibited by server")

	// ErrResourceShortage indicates the server lacks resources to handle the request.
	ErrResourceShortage = errors.New("SSH server resource shortage")

	// ErrChannelOpen indicates a generic channel open failure.
	ErrChannelOpen = errors.New("failed to open SSH channel")

	// ErrNotConnected indicates an operation was attempted without an active connection.
	ErrNotConnected = errors.New("not connected")

	// ErrHostKeyMismatch indicates the host key doesn't match expected value.
	ErrHostKeyMismatch = errors.New("host key verification failed: key mismatch (possible MITM attack)")

	// ErrHostNotInKnownHosts indicates the host is not in known_hosts file.
	ErrHostNotInKnownHosts = errors.New("host key verification failed: host not found in known_hosts")

	// ErrNoSSHAgent indicates SSH agent is not available.
	ErrNoSSHAgent = errors.New("SSH agent not available: ensure SSH_AUTH_SOCK is set and ssh-agent is running")

	// ErrPassphraseKey indicates the SSH key requires a passphrase.
	ErrPassphraseKey = errors.New("SSH key is passphrase-protected (use unencrypted key or SSH agent)")

	// ErrIdentityKeyNotFound indicates the identity file key was not found in SSH agent.
	ErrIdentityKeyNotFound = errors.New("identity file key not found in SSH agent")

	// ErrResolveConfig indicates failure resolving SSH config.
	ErrResolveConfig = errors.New("failed to resolve SSH config")

	// ErrLoadHostKey indicates failure loading host key callback.
	ErrLoadHostKey = errors.New("failed to load host key callback")

	// ErrConnect indicates failure connecting to remote host.
	ErrConnect = errors.New("failed to connect")

	// ErrInitSFTP indicates failure initializing SFTP client.
	ErrInitSFTP = errors.New("failed to initialize SFTP client")

	// ErrReadIdentityFile indicates failure reading identity file.
	ErrReadIdentityFile = errors.New("failed to read identity file")

	// ErrParseIdentityFile indicates failure parsing identity file.
	ErrParseIdentityFile = errors.New("failed to parse identity file")

	// ErrParseSSHKey indicates failure parsing SSH key.
	ErrParseSSHKey = errors.New("failed to parse SSH key")

	// ErrInvalidKeyFormat indicates invalid SSH key format.
	ErrInvalidKeyFormat = errors.New("invalid SSH key format")

	// ErrGetAgentSigners indicates failure getting signers from SSH agent.
	ErrGetAgentSigners = errors.New("failed to get signers from SSH agent")

	// ErrGetPipe indicates failure getting pipe for session.
	ErrGetPipe = errors.New("failed to get pipe")

	// ErrStartCommand indicates failure starting command.
	ErrStartCommand = errors.New("failed to start command")

	// ErrCommandFailed indicates command execution failed.
	ErrCommandFailed = errors.New("command failed")

	// ErrWriteStdin indicates failure writing to stdin.
	ErrWriteStdin = errors.New("failed to write to stdin")

	// ErrCloseStdin indicates failure closing stdin.
	ErrCloseStdin = errors.New("failed to close stdin")

	// ErrKnownHosts indicates failure with known_hosts file.
	ErrKnownHosts = errors.New("known_hosts error")

	// ErrCreateSSHDir indicates failure creating .ssh directory.
	ErrCreateSSHDir = errors.New("failed to create .ssh directory")

	// ErrHostKeyVerification indicates host key verification failed.
	ErrHostKeyVerification = errors.New("host key verification failed")

	// ErrCreateRemoteFile indicates failure creating remote file.
	ErrCreateRemoteFile = errors.New("failed to create remote file")

	// ErrSetPermissions indicates failure setting file permissions.
	ErrSetPermissions = errors.New("failed to set file permissions")

	// ErrOpenLocalFile indicates failure opening local file.
	ErrOpenLocalFile = errors.New("failed to open local file")

	// ErrWriteFile indicates failure writing file content.
	ErrWriteFile = errors.New("failed to write file content")

	// ErrCloseFile indicates failure closing file.
	ErrCloseFile = errors.New("failed to close file")

	// ErrDialUnixSocket indicates failure dialing remote unix socket.
	ErrDialUnixSocket = errors.New("failed to dial remote unix socket")

	// ErrClosingConnections happens when failing to close connection.
	ErrClosingConnections = errors.New("errors closing connections")
)

// Internal errors (not exported, used for legacy compatibility during transition).
var errInvalidPort = errors.New("invalid port in SSH config")

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
