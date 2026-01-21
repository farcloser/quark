package sshprime

import "errors"

var (
	// SSH Agent.

	// ErrAgentFailedToConnect indicates SSH agent is not available.
	ErrAgentFailedToConnect = errors.New(
		"SSH agent not available: ensure SSH_AUTH_SOCK is set and ssh-agent is running",
	)
	// ErrAgentGetSignersFailed indicates failure getting signers from SSH agent.
	ErrAgentGetSignersFailed = errors.New("failed to get signers from SSH agent")

	// SSH Fingerprinter.

	// ErrFingerprintUnknownHost indicates host key verification failed.
	ErrFingerprintUnknownHost = errors.New("unknown host")
	// ErrFingerprintMismatch indicates the host key doesn't match expected value.
	ErrFingerprintMismatch = errors.New("host key verification failed: key mismatch (possible MITM attack)")

	// Config.

	// ErrConfigInvalid indicates failure resolving SSH config.
	ErrConfigInvalid = errors.New("failed to build SSH client config")

	// Signers.

	// ErrSignerNilKey indicates a nil key was provided.
	ErrSignerNilKey = errors.New("key is nil")

	// Client.

	// ErrDialUnixSocket on failure to dial the socket.
	ErrDialUnixSocket = errors.New("failed to connect to unix socket")
	// ErrSessionLimitExceeded indicates the server's MaxSessions limit was reached.
	// This typically means too many concurrent sessions on a single SSH connection.
	ErrSessionLimitExceeded = errors.New("SSH session limit exceeded (server MaxSessions reached)")
	// ErrConnectionProhibited indicates the server rejected the connection request.
	ErrConnectionProhibited = errors.New("SSH connection prohibited by server")
	// ErrResourceShortage indicates the server lacks resources to handle the request.
	ErrResourceShortage = errors.New("SSH server resource shortage")
	// ErrChannelOpen indicates a generic channel open failure.
	ErrChannelOpen = errors.New("failed to open SSH channel")
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
)
