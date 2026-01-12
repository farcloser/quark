package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	filesystem2 "github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/fault"
)

//nolint:gochecknoglobals
var (
	fing       *Fingerprinter
	fingCreate sync.Once
)

// GetFingerprinter returns a Fingerprinter singleton.
func GetFingerprinter() *Fingerprinter {
	fingCreate.Do(func() {
		fing = &Fingerprinter{
			fingers: make(map[string]string),
		}
	})

	return fing
}

// Fingerprinter allows managing trusted servers fingerprint.
type Fingerprinter struct {
	mu                 sync.Mutex
	fingers            map[string]string
	knownHostsCallback ssh.HostKeyCallback
}

// Trust adds a fingerprint for that host in the trust ring.
func (fin *Fingerprinter) Trust(endpoint *Endpoint, sshFingerprint string) {
	fin.mu.Lock()
	defer fin.mu.Unlock()

	fin.fingers[fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)] = sshFingerprint
}

// Clear deletes the currently trusted fingerprint for a specific host.
func (fin *Fingerprinter) Clear(hostname string) {
	fin.mu.Lock()
	defer fin.mu.Unlock()

	delete(fin.fingers, hostname)
}

// GetVerifier returns a verification mechanism against our internal trust ring.
// If useConfig is provided, we will additionally check the current host ~/.ssh/known_hosts.
//
//revive:disable:flag-parameter
func (fin *Fingerprinter) GetVerifier(withKnownHosts bool) (ssh.HostKeyCallback, error) {
	if withKnownHosts {
		fin.mu.Lock()
		defer fin.mu.Unlock()

		var err error
		if fin.knownHostsCallback == nil {
			fin.knownHostsCallback, err = getKnownHostsCallback()
			if err != nil {
				return nil, err
			}
		}
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := fin.explicitVerifier(hostname, remote, key)
		if withKnownHosts && errors.Is(err, ErrFingerprintUnknownHost) {
			err = fin.knownHostsCallback(hostname, remote, key)
		}

		return err
	}, nil
}

func (fin *Fingerprinter) explicitVerifier(hostname string, _ net.Addr, key ssh.PublicKey) error {
	fin.mu.Lock()
	defer fin.mu.Unlock()

	// Calculate the fingerprint of the received key
	actualFingerprint := ssh.FingerprintSHA256(key)
	// Look-up to see if we have one for that host
	if storedFingerprint, ok := fin.fingers[hostname]; ok {
		// Compare with expected fingerprint
		if actualFingerprint != storedFingerprint {
			return fmt.Errorf(
				"%w: expected %s, got %s for %s",
				ErrFingerprintMismatch,
				storedFingerprint,
				actualFingerprint,
				hostname,
			)
		}

		return nil
	}

	return fmt.Errorf("%w", ErrFingerprintUnknownHost)
}

// getKnownHostsCallback creates a host key knownHostsCallback that verifies against ~/.ssh/known_hosts.
func getKnownHostsCallback() (ssh.HostKeyCallback, error) {
	home := filesystem2.HomeDir()

	// Standard known_hosts path
	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")

	// Check if known_hosts exists, create if it does not
	if _, err := os.Stat(knownHostsPath); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
		}

		sshDir := filepath.Join(home, ".ssh")
		if err := os.MkdirAll(sshDir, filesystem2.DirPermissionsPrivate); err != nil {
			return nil, fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
		}

		//nolint:gosec
		file, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_WRONLY, filesystem2.FilePermissionsPrivate)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", fault.ErrWriteFailure, err)
		}

		_ = file.Close()
	}

	// Load known_hosts
	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	// Wrap the knownHostsCallback to provide better error messages
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := hostKeyCallback(hostname, remote, key)
		if err != nil {
			// Check if this is a key mismatch error
			var keyErr *knownhosts.KeyError
			if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
				return fmt.Errorf(
					"%w for %s. If you trust this host, remove the old key from %s and retry",
					ErrFingerprintMismatch,
					hostname,
					knownHostsPath,
				)
			}

			// Check if this is an unknown host error
			if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
				return fmt.Errorf(
					"%w: %s. To add this host, run: ssh-keyscan -H %s >> %s",
					ErrFingerprintUnknownHost,
					hostname,
					hostname,
					knownHostsPath,
				)
			}

			// Unexpected error
			return fmt.Errorf("%w: %w", fault.ErrSystemFailure, err)
		}

		return nil
	}, nil
}
