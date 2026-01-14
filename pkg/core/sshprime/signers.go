package sshprime

import (
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/fault"
)

// SignerFromKey creates an ssh.Signer from a private key.
// If the key is encrypted, Key.Passphrase must be set.
func SignerFromKey(key *Key) (ssh.Signer, error) {
	if key == nil {
		return nil, ErrSignerNilKey
	}

	return key.getSigner()
}

// SignerFromAgent returns a signer from the SSH agent matching the given fingerprint.
// The fingerprint should be in SHA256 format (e.g., "SHA256:...").
// If fingerprint is empty, returns the first available signer.
func SignerFromAgent(fingerprint string) (ssh.Signer, error) {
	signers, err := GetAgent().Signers()
	if err != nil {
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
