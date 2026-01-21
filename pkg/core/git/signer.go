package git

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/config"
	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/core/sshprime"
	"github.com/farcloser/quark/pkg/fault"
)

// sshSigner implements object.Signer for SSH key signing.
// This creates signatures in Git's SSH signature format (git 2.34+).
type sshSigner struct {
	signer ssh.Signer
}

// newSSHSigner creates a new SSH signer from an ssh.Signer.
// The ssh.Signer can be obtained from ssh-agent or by parsing a private key.
func newSSHSigner(signer ssh.Signer) *sshSigner {
	return &sshSigner{signer: signer}
}

// Sign implements object.Signer.
// It creates an SSH signature over the commit content.
func (s *sshSigner) Sign(message io.Reader) ([]byte, error) {
	content, err := io.ReadAll(message)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	// Create the signature blob that will be signed.
	// Git's SSH signature format signs a structured blob, not the raw content.
	signedData := buildSSHSignedData(sshSigNamespace, sshSigHashAlgo, content)

	// Sign the data.
	sig, err := s.signer.Sign(nil, signedData)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureSigningFailed, err)
	}

	// Build the SSH signature blob and armor it.
	return armorSSHSignature(buildSSHSignatureBlob(s.signer.PublicKey(), sig)), nil
}

// resolveSigner resolves an SSH signer using the following priority:
//  1. If key contains a private key with passphrase → use it directly
//  2. If key is encrypted without passphrase → extract pubkey, get signer from agent
//  3. If key contains a public key → get signer from agent
//  4. If key is nil → read git config (user.signingkey), resolve and proceed as above
//
// Returns fault.ErrNotFound if no signer can be resolved.
func (r *Repo) resolveSigner(key sshprime.Key) (ssh.Signer, error) {
	// If a key is provided, try to use it directly
	if key != nil {
		signers := sshprime.GetSigners([]sshprime.Key{key}, "", false)
		if len(signers) == 0 {
			return nil, fmt.Errorf("%w: unable to get signer from key", fault.ErrNotFound)
		}

		return signers[0], nil
	}

	// No key provided, try git config
	configFing, keyBytes, err := resolveSignerFromConfig(r)
	if err != nil {
		return nil, err
	}

	if configFing != "" {
		return signerFromAgent(configFing)
	}

	key, err = sshprime.NewKey(keyBytes, nil, true)
	//nolint:wrapcheck
	if err != nil {
		return nil, err
	}

	signers := sshprime.GetSigners([]sshprime.Key{key}, "", false)
	if len(signers) == 0 {
		return nil, fmt.Errorf("%w: unable to get signer from key", fault.ErrNotFound)
	}

	return signers[0], nil
}

// resolveSignerFromConfig reads git config to find the signing key.
// Supports:
//   - key::<fingerprint> format (e.g., "key::SHA256:abc123...")
//   - File path (e.g., "~/.ssh/id_ed25519.pub")
func resolveSignerFromConfig(repo *Repo) (string, []byte, error) {
	cfg, err := repo.repo.ConfigScoped(config.GlobalScope)
	if err != nil {
		return "", nil, fmt.Errorf("%w: failed to read git config: %w", fault.ErrReadFailure, err)
	}

	// Check gpg.format - must be "ssh" for SSH signing
	gpgFormat := cfg.Raw.Section("gpg").Option("format")
	if gpgFormat != "" && gpgFormat != "ssh" {
		return "", nil, fmt.Errorf("%w: gpg.format is %q, not ssh", ErrSigningNotConfigured, gpgFormat)
	}

	// Get user.signingkey
	signingKey := cfg.Raw.Section("user").Option("signingkey")
	if signingKey == "" {
		return "", nil, fmt.Errorf("%w: user.signingkey not set", ErrSigningNotConfigured)
	}

	// Handle key::<fingerprint> format - direct agent lookup
	if fingerprint, found := strings.CutPrefix(signingKey, "key::"); found {
		return fingerprint, nil, nil
	}

	// Handle file path
	keyPath := signingKey

	// Expand ~
	if expanded, found := strings.CutPrefix(keyPath, "~/"); found {
		keyPath = filepath.Join(filesystem.HomeDir(), expanded)
	}

	// Read the file and resolve via GetSigners
	// #nosec G304 -- keyPath comes from git config
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", nil, fmt.Errorf("%w: failed to read signing key %s: %w", fault.ErrReadFailure, keyPath, err)
	}

	return "", keyBytes, nil
}

// signerFromAgent returns a signer from the SSH agent matching the given fingerprint.
// The fingerprint should be in SHA256 format (e.g., "SHA256:...").
// If fingerprint is empty, returns the first available signer.
func signerFromAgent(fingerprint string) (ssh.Signer, error) {
	signers, err := sshprime.GetAgent().Signers()
	if err != nil {
		//nolint:wrapcheck
		return nil, err
	}

	if len(signers) == 0 {
		return nil, fault.ErrNotFound
	}

	if fingerprint == "" {
		return signers[0], nil
	}

	for _, s := range signers {
		if ssh.FingerprintSHA256(s.PublicKey()) == fingerprint {
			return s, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", fault.ErrNotFound, fingerprint)
}
