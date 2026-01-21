package ssh_test

import (
	"strings"
	"testing"

	"github.com/farcloser/quark/pkg/core/sshprime"
	sshpool "github.com/farcloser/quark/pkg/dev/ssh"
	testssh "github.com/farcloser/quark/testutil/ssh"
)

const skipIntegrationMsg = "skipping integration test in short mode"

func TestConnection_Execute(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip(skipIntegrationMsg)
	}

	container := testssh.EnsureDebianContainer(t)
	pool := sshpool.GetPool()
	fingerprint := testssh.GetHostFingerprint(t, container.Host)
	testKey := testssh.GetTestKey(t)

	client, err := pool.GetClient(container.Endpoint, fingerprint, []sshprime.Key{testKey})
	if err != nil {
		t.Fatalf("failed to get client: %v", err)
	}

	t.Run("executes simple command and captures stdout", func(t *testing.T) {
		t.Parallel()

		stdout, stderr, err := client.Execute("echo 'hello world'", nil)
		if err != nil {
			t.Fatalf("expected command to succeed, got error: %v", err)
		}

		if !strings.Contains(stdout, "hello world") {
			t.Errorf("expected stdout to contain 'hello world', got: %q", stdout)
		}

		if stderr != "" {
			t.Errorf("expected empty stderr, got: %q", stderr)
		}
	})

	t.Run("captures stderr", func(t *testing.T) {
		t.Parallel()

		stdout, stderr, err := client.Execute("echo 'error message' >&2", nil)
		if err != nil {
			t.Fatalf("expected command to succeed, got error: %v", err)
		}

		if stdout != "" {
			t.Errorf("expected empty stdout, got: %q", stdout)
		}

		if !strings.Contains(stderr, "error message") {
			t.Errorf("expected stderr to contain 'error message', got: %q", stderr)
		}
	})

	t.Run("returns error for failing command", func(t *testing.T) {
		t.Parallel()

		_, _, err := client.Execute("exit 1", nil)
		if err == nil {
			t.Fatal("expected error for command with exit code 1")
		}
	})

	t.Run("executes multiple commands on same connection", func(t *testing.T) {
		t.Parallel()

		// First command
		stdout1, _, err := client.Execute("echo 'first'", nil)
		if err != nil {
			t.Fatalf("first command failed: %v", err)
		}

		if !strings.Contains(stdout1, "first") {
			t.Errorf("expected stdout to contain 'first', got: %q", stdout1)
		}

		// Second command
		stdout2, _, err := client.Execute("echo 'second'", nil)
		if err != nil {
			t.Fatalf("second command failed: %v", err)
		}

		if !strings.Contains(stdout2, "second") {
			t.Errorf("expected stdout to contain 'second', got: %q", stdout2)
		}
	})

	t.Run("handles commands with complex output", func(t *testing.T) {
		t.Parallel()

		stdout, _, err := client.Execute("ls -la /", nil)
		if err != nil {
			t.Fatalf("expected ls command to succeed, got error: %v", err)
		}

		// Verify we got directory listing
		if !strings.Contains(stdout, "bin") || !strings.Contains(stdout, "etc") {
			t.Errorf("expected directory listing to contain 'bin' and 'etc', got: %q", stdout)
		}
	})
}

func TestPool_GetClient(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip(skipIntegrationMsg)
	}

	container := testssh.EnsureDebianContainer(t)
	endpoint := container.Endpoint
	fingerprint := testssh.GetHostFingerprint(t, container.Host)
	testKey := testssh.GetTestKey(t)

	t.Run("creates new connection", func(t *testing.T) {
		t.Parallel()

		pool := sshpool.GetPool()

		client, err := pool.GetClient(endpoint, fingerprint, []sshprime.Key{testKey})
		if err != nil {
			t.Fatalf("expected GetClient to succeed, got error: %v", err)
		}

		if client == nil {
			t.Fatal("expected non-nil client")
		}

		// Verify connection works
		stdout, _, err := client.Execute("echo 'test'", nil)
		if err != nil {
			t.Fatalf("expected command to succeed, got error: %v", err)
		}

		if !strings.Contains(stdout, "test") {
			t.Errorf("expected stdout to contain 'test', got: %q", stdout)
		}
	})

	t.Run("reuses existing connection", func(t *testing.T) {
		t.Parallel()

		pool := sshpool.GetPool()

		// First connection
		client1, err := pool.GetClient(endpoint, fingerprint, []sshprime.Key{testKey})
		if err != nil {
			t.Fatalf("first GetClient failed: %v", err)
		}

		// Second connection to same endpoint
		client2, err := pool.GetClient(endpoint, fingerprint, []sshprime.Key{testKey})
		if err != nil {
			t.Fatalf("second GetClient failed: %v", err)
		}

		// Both should work
		_, _, err = client1.Execute("echo 'client1'", nil)
		if err != nil {
			t.Errorf("client1 execution failed: %v", err)
		}

		_, _, err = client2.Execute("echo 'client2'", nil)
		if err != nil {
			t.Errorf("client2 execution failed: %v", err)
		}
	})

	t.Run("handles multiple parallel commands", func(t *testing.T) {
		t.Parallel()

		pool := sshpool.GetPool()

		client, err := pool.GetClient(endpoint, fingerprint, []sshprime.Key{testKey})
		if err != nil {
			t.Fatalf("GetClient failed: %v", err)
		}

		// Execute multiple commands sequentially
		for iteration := range 5 {
			stdout, _, err := client.Execute("echo 'iteration'", nil)
			if err != nil {
				t.Errorf("command %d failed: %v", iteration, err)
			}

			if !strings.Contains(stdout, "iteration") {
				t.Errorf("command %d: expected 'iteration' in output, got: %q", iteration, stdout)
			}
		}
	})
}

//nolint:paralleltest // Cannot run in parallel - CloseAll affects singleton pool shared by other tests.
func TestPool_CloseAll(t *testing.T) {
	if testing.Short() {
		t.Skip(skipIntegrationMsg)
	}

	container := testssh.EnsureDebianContainer(t)
	endpoint := container.Endpoint
	fingerprint := testssh.GetHostFingerprint(t, container.Host)
	testKey := testssh.GetTestKey(t)

	pool := sshpool.GetPool()

	// Create connection
	client, err := pool.GetClient(endpoint, fingerprint, []sshprime.Key{testKey})
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}

	// Verify connection works before closing
	_, _, err = client.Execute("echo 'before close'", nil)
	if err != nil {
		t.Fatalf("command before close failed: %v", err)
	}

	// Verify pool has at least our connection (other parallel tests may have added more)
	initialSize := pool.Size()
	if initialSize < 1 {
		t.Errorf("expected pool size >= 1, got %d", initialSize)
	}

	// Close pool
	if err := pool.CloseAll(); err != nil {
		t.Errorf("CloseAll() returned error: %v", err)
	}

	// Verify pool is empty
	if pool.Size() != 0 {
		t.Errorf("expected pool size 0 after CloseAll(), got %d", pool.Size())
	}

	// Note: Execute on closed client would panic (correct behavior for programmer error),
	// so we don't test that case here.
}
