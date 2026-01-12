package ssh

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
	// ErrSignerParseKey indicates failure parsing private key.
	ErrSignerParseKey = errors.New("failed to parse private key")
)
