package sock

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/dev/filesystem"
	"github.com/farcloser/quark/dev/ssh"
	"github.com/farcloser/quark/dev/utilities"
)

const (
	runtimeSubDir = "sock"
	socketFile    = "socket.sock"
)

// processToken is a random value generated once at process start.
// Used to create process-unique socket paths for cross-process safety.
//
//nolint:gochecknoglobals
var processToken = utilities.GenerateProcessToken()

// tunnelManager coordinates tunnel sharing within a single process.
//
//nolint:gochecknoglobals
var tunnelManager = &manager{
	tunnels: make(map[string]*managedEntry),
}

type manager struct {
	mu      sync.Mutex
	tunnels map[string]*managedEntry
}

type managedEntry struct {
	tunnel   *Tunnel
	refCount int
}

// Tunnel represents a local socket that forwards to a remote socket over SSH.
// Safe for concurrent access within the same process.
type Tunnel struct {
	localPath  string
	remotePath string
	listener   net.Listener
	conn       ssh.Connection
	log        *slog.Logger
	wg         sync.WaitGroup
	closed     chan struct{}
}

// Acquire gets or creates a tunnel to the remote socket path over the given SSH connection.
// Multiple callers within the same process will share the same tunnel.
// Call Release() when done to allow cleanup when all holders release.
func Acquire(conn ssh.Connection, remotePath string, log *slog.Logger) (*Tunnel, error) {
	// Key combines endpoint and remote path for uniqueness
	key := conn.Endpoint() + ":" + remotePath

	tunnelManager.mu.Lock()
	defer tunnelManager.mu.Unlock()

	// Check if we already have a tunnel for this combination
	if entry, exists := tunnelManager.tunnels[key]; exists {
		entry.refCount++

		log.Debug("reusing existing tunnel",
			"local", entry.tunnel.localPath,
			"remote", remotePath,
			"refCount", entry.refCount)

		return entry.tunnel, nil
	}

	// Create new tunnel
	tunnel, err := createTunnel(conn, remotePath, log)
	if err != nil {
		return nil, err
	}

	tunnelManager.tunnels[key] = &managedEntry{
		tunnel:   tunnel,
		refCount: 1,
	}

	log.Debug("created new tunnel",
		"local", tunnel.localPath,
		"remote", remotePath)

	return tunnel, nil
}

// createTunnel creates a new tunnel for the given connection and remote path.
func createTunnel(conn ssh.Connection, remotePath string, log *slog.Logger) (*Tunnel, error) {
	runtimeDir, err := filesystem.RuntimeDir()
	if err != nil {
		return nil, err
	}

	// Build path: $XDG_RUNTIME_DIR/sock/<sha256(endpoint)>/<sha256(remotePath)>/<processToken>/socket.sock
	endpointHash := hashString(conn.Endpoint())
	remoteHash := hashString(remotePath)
	socketDir := filepath.Join(runtimeDir, runtimeSubDir, endpointHash, remoteHash, processToken)

	if err := os.MkdirAll(socketDir, filesystem.DirPermissionsPrivate); err != nil {
		return nil, fmt.Errorf("%w: socket directory: %w", fault.ErrFilesystemFailure, err)
	}

	localPath := filepath.Join(socketDir, socketFile)

	// Remove stale socket if it exists
	if err := os.Remove(localPath); err != nil && !os.IsNotExist(err) {
		log.Warn("failed to remove stale socket", "path", localPath, "error", err)
	}

	listener, err := net.Listen("unix", localPath) //nolint:noctx // Unix socket - local IPC
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
	}

	tunnel := &Tunnel{
		localPath:  localPath,
		remotePath: remotePath,
		listener:   listener,
		conn:       conn,
		log:        log,
		closed:     make(chan struct{}),
	}

	tunnel.wg.Add(1)

	go tunnel.acceptLoop()

	log.Debug("tunnel started",
		"local", localPath,
		"remote", remotePath)

	return tunnel, nil
}

// hashString returns a 4-byte (8 hex char) hash of the input string.
// Shortened to keep Unix socket paths under OS limits (104 bytes on macOS).
func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))

	return hex.EncodeToString(hash[:4])
}

// Release releases this holder's claim on the tunnel.
// When the last holder releases, the tunnel is cleaned up.
func (t *Tunnel) Release() {
	key := t.conn.Endpoint() + ":" + t.remotePath

	tunnelManager.mu.Lock()
	defer tunnelManager.mu.Unlock()

	entry, exists := tunnelManager.tunnels[key]
	if !exists {
		return
	}

	entry.refCount--

	t.log.Debug("releasing tunnel",
		"local", t.localPath,
		"refCount", entry.refCount)

	if entry.refCount <= 0 {
		delete(tunnelManager.tunnels, key)
		t.shutdown()
	}
}

// LocalPath returns the local socket path.
func (t *Tunnel) LocalPath() string {
	return t.localPath
}

// RemotePath returns the remote socket path.
func (t *Tunnel) RemotePath() string {
	return t.remotePath
}

// shutdown closes the tunnel and cleans up resources.
func (t *Tunnel) shutdown() {
	close(t.closed)

	if err := t.listener.Close(); err != nil {
		t.log.Warn("failed to close listener", "error", err)
	}

	// Wait briefly for connections to finish, then proceed
	done := make(chan struct{})

	go func() {
		t.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown
	case <-time.After(2 * time.Second):
		t.log.Debug("tunnel shutdown timeout, proceeding with cleanup")
	}

	// Remove socket file
	if err := os.Remove(t.localPath); err != nil && !os.IsNotExist(err) {
		t.log.Warn("failed to remove socket file", "error", err)
	}

	// Try to remove socket directories (will fail if not empty, which is fine)
	_ = os.Remove(filepath.Dir(t.localPath))                             // processToken dir
	_ = os.Remove(filepath.Dir(filepath.Dir(t.localPath)))               // remoteHash dir
	_ = os.Remove(filepath.Dir(filepath.Dir(filepath.Dir(t.localPath)))) // endpointHash dir

	t.log.Debug("tunnel closed")
}

// acceptLoop accepts connections and forwards them to the remote socket.
func (t *Tunnel) acceptLoop() {
	defer t.wg.Done()

	for {
		localConn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
				t.log.Error("failed to accept connection", "error", err)

				continue
			}
		}

		t.wg.Add(1)

		go t.handleConnection(localConn)
	}
}

// handleConnection forwards data between local and remote connections.
func (t *Tunnel) handleConnection(localConn net.Conn) {
	defer t.wg.Done()
	defer localConn.Close()

	remoteConn, err := t.conn.DialUnix(t.remotePath)
	if err != nil {
		t.log.Error("failed to connect to remote socket",
			"remote", t.remotePath,
			"error", err)

		return
	}

	defer remoteConn.Close()

	done := make(chan struct{}, 2)

	go func() {
		_, _ = io.Copy(remoteConn, localConn)

		done <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(localConn, remoteConn)

		done <- struct{}{}
	}()

	<-done
}
