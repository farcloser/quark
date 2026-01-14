package ssh

import (
	"errors"
)

// Exported errors for consumer type checking.
var (
	// ErrFailedToConnect when failing to connect the client to the remote host.
	ErrFailedToConnect = errors.New("failed to connect to node")

	// ErrClosingConnections happens when failing to close connection.
	ErrClosingConnections = errors.New("errors closing connections")
)
