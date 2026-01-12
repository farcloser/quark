//nolint:paralleltest // home manipulation
package ssh_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/core/ssh"
)

func TestGetFingerprinter_Singleton(t *testing.T) {
	t.Parallel()

	fp1 := ssh.GetFingerprinter()
	fp2 := ssh.GetFingerprinter()

	if fp1 != fp2 {
		t.Error("GetFingerprinter should return the same instance")
	}
}

func TestFingerprinter_TrustThenVerify_Success(t *testing.T) {
	t.Parallel()

	pubKey, _ := generateTestKey(t)
	fingerprint := cryptossh.FingerprintSHA256(pubKey)

	// Use unique hostname to avoid conflicts with other tests
	endpoint := &ssh.Endpoint{Host: "test-trust-success.example.com", Port: 22}
	hostname := "test-trust-success.example.com:22"

	fp := ssh.GetFingerprinter()
	fp.Trust(endpoint, fingerprint)

	defer fp.Clear(hostname)

	verifier, _ := fp.GetVerifier(false)

	err := verifier(hostname, nil, pubKey)
	if err != nil {
		t.Errorf("verifier should succeed for trusted key: %v", err)
	}
}

func TestFingerprinter_TrustThenVerify_Mismatch(t *testing.T) {
	t.Parallel()

	pubKey1, _ := generateTestKey(t)
	pubKey2, _ := generateTestKey(t)

	endpoint := &ssh.Endpoint{Host: "test-trust-mismatch.example.com", Port: 22}
	hostname := "test-trust-mismatch.example.com:22"

	fp := ssh.GetFingerprinter()
	fp.Trust(endpoint, cryptossh.FingerprintSHA256(pubKey1))

	defer fp.Clear(hostname)

	verifier, _ := fp.GetVerifier(false)

	err := verifier(hostname, nil, pubKey2)
	if err == nil {
		t.Fatal("verifier should fail for mismatched key")
	}

	if !errors.Is(err, ssh.ErrFingerprintMismatch) {
		t.Errorf("expected ErrFingerprintMismatch, got: %v", err)
	}
}

func TestFingerprinter_Verifier_UnknownHost(t *testing.T) {
	t.Parallel()

	pubKey, _ := generateTestKey(t)

	fp := ssh.GetFingerprinter()
	verifier, _ := fp.GetVerifier(false)

	// Use hostname that was never trusted
	err := verifier("never-trusted.example.com:22", nil, pubKey)
	if err == nil {
		t.Fatal("verifier should fail for unknown host")
	}

	if !errors.Is(err, ssh.ErrFingerprintUnknownHost) {
		t.Errorf("expected ErrFingerprintUnknownHost, got: %v", err)
	}
}

func TestFingerprinter_Clear(t *testing.T) {
	t.Parallel()

	pubKey, _ := generateTestKey(t)
	fingerprint := cryptossh.FingerprintSHA256(pubKey)

	endpoint := &ssh.Endpoint{Host: "test-clear.example.com", Port: 22}
	hostname := "test-clear.example.com:22"

	fp := ssh.GetFingerprinter()
	fp.Trust(endpoint, fingerprint)

	// Verify trust works
	verifier, _ := fp.GetVerifier(false)

	err := verifier(hostname, nil, pubKey)
	if err != nil {
		t.Fatalf("verifier should succeed before clear: %v", err)
	}

	// Clear and verify it fails
	fp.Clear(hostname)

	err = verifier(hostname, nil, pubKey)
	if err == nil {
		t.Fatal("verifier should fail after clear")
	}

	if !errors.Is(err, ssh.ErrFingerprintUnknownHost) {
		t.Errorf("expected ErrFingerprintUnknownHost after clear, got: %v", err)
	}
}

// TestFingerprinter_KnownHostsVerifier tests the actual GetKnownHostsVerifier production code.
// This test manipulates HOME to use a temp directory with controlled known_hosts content.
// Cannot be parallel due to singleton caching and HOME manipulation.
func TestFingerprinter_KnownHostsVerifier(t *testing.T) {
	// Create temp home with .ssh directory
	tmpHome := t.TempDir()
	sshDir := filepath.Join(tmpHome, ".ssh")

	err := os.MkdirAll(sshDir, filesystem.DirPermissionsPrivate)
	if err != nil {
		t.Fatalf("failed to create .ssh dir: %v", err)
	}

	// Generate a test key and create known_hosts entry
	pubKey, _ := generateTestKey(t)
	knownHostname := "known.example.com"
	knownHostsEntry := fmt.Sprintf("%s %s %s\n",
		knownHostname,
		pubKey.Type(),
		base64.StdEncoding.EncodeToString(pubKey.Marshal()),
	)

	knownHostsPath := filepath.Join(sshDir, "known_hosts")

	err = os.WriteFile(knownHostsPath, []byte(knownHostsEntry), filesystem.FilePermissionsPrivate)
	if err != nil {
		t.Fatalf("failed to create known_hosts: %v", err)
	}

	// Set HOME to temp directory
	t.Setenv("HOME", tmpHome)

	// Get the verifier from production code
	fp := ssh.GetFingerprinter()

	callback, err := fp.GetVerifier(true)
	if err != nil {
		t.Fatalf("GetKnownHostsVerifier failed: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	t.Run("Success", func(t *testing.T) {
		err := callback(knownHostname+":22", addr, pubKey)
		if err != nil {
			t.Errorf("callback should succeed for known host: %v", err)
		}
	})

	t.Run("Mismatch", func(t *testing.T) {
		differentKey, _ := generateTestKey(t)

		err := callback(knownHostname+":22", addr, differentKey)
		if err == nil {
			t.Fatal("callback should fail for mismatched key")
		}

		if !errors.Is(err, ssh.ErrFingerprintMismatch) {
			t.Errorf("expected ErrFingerprintMismatch, got: %v", err)
		}
	})

	t.Run("UnknownHost", func(t *testing.T) {
		unknownKey, _ := generateTestKey(t)

		err := callback("unknown.example.com:22", addr, unknownKey)
		if err == nil {
			t.Fatal("callback should fail for unknown host")
		}

		if !errors.Is(err, ssh.ErrFingerprintUnknownHost) {
			t.Errorf("expected ErrFingerprintUnknownHost, got: %v", err)
		}
	})
}

// generateTestKey generates an ed25519 key pair for testing.
func generateTestKey(t *testing.T) (cryptossh.PublicKey, cryptossh.Signer) {
	t.Helper()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := cryptossh.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	sshPubKey, err := cryptossh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}

	return sshPubKey, signer
}
