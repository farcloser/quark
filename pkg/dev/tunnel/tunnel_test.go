package tunnel_test

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/farcloser/quark/pkg/core/sshprime"
	devssh "github.com/farcloser/quark/pkg/dev/ssh"
	"github.com/farcloser/quark/pkg/dev/tunnel"
	testssh "github.com/farcloser/quark/testutil/ssh"
)

const skipIntegrationMsg = "skipping integration test in short mode"

// mockConnection implements ssh.Connection for unit testing.
type mockConnection struct {
	endpoint   string
	dialUnixFn func(remotePath string) (net.Conn, error)
}

func (m *mockConnection) Execute(string, []byte) (string, string, error) {
	return "", "", nil
}

func (m *mockConnection) ExecuteStreaming(string, io.Writer, io.Writer, []byte) error {
	return nil
}

func (m *mockConnection) UploadFile(string, string) error {
	return nil
}

func (m *mockConnection) UploadData([]byte, string) error {
	return nil
}

func (m *mockConnection) DialUnix(remotePath string) (net.Conn, error) {
	if m.dialUnixFn != nil {
		return m.dialUnixFn(remotePath)
	}

	//nolint:nilnil
	return nil, nil
}

func (m *mockConnection) Endpoint() string {
	return m.endpoint
}

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestAcquire_CreatesTunnel(t *testing.T) {
	t.Parallel()

	conn := &mockConnection{endpoint: "test-host:22"}
	remotePath := "/tmp/test.sock"

	tun, err := tunnel.Acquire(conn, remotePath, testLogger())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	defer tun.Release()

	if tun.LocalPath() == "" {
		t.Error("expected non-empty LocalPath")
	}

	if tun.RemotePath() != remotePath {
		t.Errorf("expected RemotePath %q, got %q", remotePath, tun.RemotePath())
	}

	// Verify socket file was created
	if _, err := os.Stat(tun.LocalPath()); os.IsNotExist(err) {
		t.Error("expected socket file to exist")
	}
}

func TestAcquire_ReusesSameTunnel(t *testing.T) {
	t.Parallel()

	conn := &mockConnection{endpoint: "reuse-host:22"}
	remotePath := "/tmp/reuse.sock"
	log := testLogger()

	tun1, err := tunnel.Acquire(conn, remotePath, log)
	if err != nil {
		t.Fatalf("first Acquire failed: %v", err)
	}

	defer tun1.Release()

	tun2, err := tunnel.Acquire(conn, remotePath, log)
	if err != nil {
		t.Fatalf("second Acquire failed: %v", err)
	}

	defer tun2.Release()

	// Should be the same tunnel instance
	if tun1.LocalPath() != tun2.LocalPath() {
		t.Errorf("expected same tunnel, got different LocalPaths: %q vs %q", tun1.LocalPath(), tun2.LocalPath())
	}
}

func TestAcquire_DifferentRemotePaths_CreatesDifferentTunnels(t *testing.T) {
	t.Parallel()

	conn := &mockConnection{endpoint: "multi-host:22"}
	log := testLogger()

	tun1, err := tunnel.Acquire(conn, "/tmp/path1.sock", log)
	if err != nil {
		t.Fatalf("first Acquire failed: %v", err)
	}

	defer tun1.Release()

	tun2, err := tunnel.Acquire(conn, "/tmp/path2.sock", log)
	if err != nil {
		t.Fatalf("second Acquire failed: %v", err)
	}

	defer tun2.Release()

	// Should be different tunnels
	if tun1.LocalPath() == tun2.LocalPath() {
		t.Error("expected different tunnels for different remote paths")
	}
}

func TestRelease_CleansUpOnLastRelease(t *testing.T) {
	t.Parallel()

	conn := &mockConnection{endpoint: "cleanup-host:22"}
	remotePath := "/tmp/cleanup.sock"
	log := testLogger()

	tun1, err := tunnel.Acquire(conn, remotePath, log)
	if err != nil {
		t.Fatalf("first Acquire failed: %v", err)
	}

	tun2, err := tunnel.Acquire(conn, remotePath, log)
	if err != nil {
		t.Fatalf("second Acquire failed: %v", err)
	}

	localPath := tun1.LocalPath()

	// First release - socket should still exist
	tun1.Release()

	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		t.Error("socket should still exist after first release")
	}

	// Second release - socket should be cleaned up
	tun2.Release()

	if _, err := os.Stat(localPath); !os.IsNotExist(err) {
		t.Error("socket should be removed after last release")
	}
}

func TestRelease_DoubleRelease_NoOp(t *testing.T) {
	t.Parallel()

	conn := &mockConnection{endpoint: "double-release:22"}
	remotePath := "/tmp/double.sock"

	tun, err := tunnel.Acquire(conn, remotePath, testLogger())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	// Double release should not panic
	tun.Release()
	tun.Release() // Should be no-op
}

func TestTunnel_DataForwarding(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip(skipIntegrationMsg)
	}

	// Create a local "remote" socket to simulate the remote end
	remoteSocketPath := t.TempDir() + "/remote.sock"

	remoteListener, err := net.Listen("unix", remoteSocketPath)
	if err != nil {
		t.Fatalf("failed to create remote socket: %v", err)
	}

	defer remoteListener.Close()

	// Echo server on the "remote" socket
	var serverWg sync.WaitGroup

	serverWg.Add(1)

	go func() {
		defer serverWg.Done()

		conn, err := remoteListener.Accept()
		if err != nil {
			return
		}

		defer conn.Close()

		// Echo back whatever is received
		buf := make([]byte, 1024)

		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		_, _ = conn.Write(buf[:n])
	}()

	// Mock connection that dials our local "remote" socket
	conn := &mockConnection{
		endpoint: "forward-test:22",
		dialUnixFn: func(string) (net.Conn, error) {
			return net.Dial("unix", remoteSocketPath)
		},
	}

	tun, err := tunnel.Acquire(conn, remoteSocketPath, testLogger())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	defer tun.Release()

	// Connect to the tunnel's local socket
	localConn, err := net.Dial("unix", tun.LocalPath())
	if err != nil {
		t.Fatalf("failed to connect to tunnel: %v", err)
	}

	defer localConn.Close()

	// Send data through the tunnel
	testData := []byte("hello through tunnel")
	if _, err := localConn.Write(testData); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// Read response
	buf := make([]byte, 1024)

	n, err := localConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("expected %q, got %q", testData, buf[:n])
	}

	serverWg.Wait()
}

// Integration test with real SSH connection.
func TestTunnel_RealSSH(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip(skipIntegrationMsg)
	}

	container := testssh.EnsureDebianContainer(t)
	pool := devssh.GetPool()
	fingerprint := testssh.GetHostFingerprint(t, container.Host)
	testKey := testssh.GetTestKey(t)

	client, err := pool.GetClient(container.Endpoint, fingerprint, []sshprime.Key{testKey})
	if err != nil {
		t.Fatalf("failed to get client: %v", err)
	}

	// Create a socket on the remote host
	remoteSocketPath := "/tmp/test-tunnel.sock"

	// Start a simple echo server on the remote
	_, _, err = client.Execute("rm -f "+remoteSocketPath, nil)
	if err != nil {
		t.Fatalf("failed to cleanup: %v", err)
	}

	// Start nc listening on unix socket in background
	_, _, err = client.Execute("nohup nc -lU "+remoteSocketPath+" -c 'cat' > /dev/null 2>&1 &", nil)
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}

	// Give it time to start
	_, _, _ = client.Execute("sleep 0.5", nil)

	// Verify socket exists
	stdout, _, err := client.Execute("test -S "+remoteSocketPath+" && echo exists", nil)
	if err != nil || stdout == "" {
		t.Skip("nc -lU not available or socket not created, skipping")
	}

	// Create tunnel
	tun, err := tunnel.Acquire(client, remoteSocketPath, testLogger())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	defer tun.Release()

	// Connect through tunnel
	localConn, err := net.Dial("unix", tun.LocalPath())
	if err != nil {
		t.Fatalf("failed to connect to tunnel: %v", err)
	}

	defer localConn.Close()

	// Send and receive data
	testData := []byte("ssh tunnel test")
	if _, err := localConn.Write(testData); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	buf := make([]byte, 1024)

	n, err := localConn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("failed to read: %v", err)
	}

	if n > 0 && string(buf[:n]) != string(testData) {
		t.Errorf("expected %q, got %q", testData, buf[:n])
	}

	// Cleanup remote
	_, _, _ = client.Execute("pkill -f 'nc -lU "+remoteSocketPath+"'", nil)
	_, _, _ = client.Execute("rm -f "+remoteSocketPath, nil)
}
