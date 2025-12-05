package sdk

import (
	"log/slog"
	"sync"

	"github.com/farcloser/quark/dev/ssh"
)

//nolint:gochecknoglobals // Singleton pattern for SSH connection pool reuse across plan executions
var (
	sshPoolOnce     sync.Once
	sshPoolInstance *ssh.Pool
)

// getSSHPool returns the global SSH connection pool singleton.
// The pool is lazily initialized on first access.
func getSSHPool() *ssh.Pool {
	sshPoolOnce.Do(func() {
		sshPoolInstance = ssh.NewPool(slog.Default())
	})

	return sshPoolInstance
}

// TearDown closes all SSH connections in the global pool.
// Should be called when the application is shutting down.
func TearDown() error {
	if sshPoolInstance != nil {
		return sshPoolInstance.CloseAll()
	}

	return nil
}
