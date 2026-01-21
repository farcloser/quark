package sshprime

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/fault"
)

// NewKey returns a usable Key from bytes and optional passphrase.
// Bytes may be an unencrypted private key, and encrypted private key, a public key, or an "authorized key".
// If insecure is true (eg: key is from filesystem) and we have a private key with no passphrase, we error out (sane
// security posture).
//
//revive:disable:flag-parameter
func NewKey(bytes, passphrase []byte, insecure bool) (Key, error) {
	newKey := &sshKey{
		unsafe: insecure,
	}

	var err error

	if len(passphrase) > 0 {
		newKey.signer, err = ssh.ParsePrivateKeyWithPassphrase(bytes, passphrase)
	} else {
		if insecure {
			return nil, fmt.Errorf("refusing to use unencrypted private key from filesystem: %w", fault.ErrInvalidArgument)
		}

		newKey.signer, err = ssh.ParsePrivateKey(bytes)
	}

	if err == nil {
		newKey.publicKey = newKey.signer.PublicKey()

		return newKey, nil
	}

	// Encrypted and passphrase does not work?
	// Then just get the pub part.
	var passphraseErr *ssh.PassphraseMissingError
	if errors.As(err, &passphraseErr) {
		newKey.publicKey = passphraseErr.PublicKey

		return newKey, nil
	}

	// Hail mary. Try to parse as a pub key
	pubKey, err := ssh.ParsePublicKey(bytes)
	if err == nil {
		newKey.publicKey = pubKey

		return newKey, nil
	}

	// Final hail mary, try to parse as an authorized key
	//nolint:dogsled
	pubKey, _, _, _, err = ssh.ParseAuthorizedKey(bytes)
	if err == nil {
		newKey.publicKey = pubKey

		return newKey, nil
	}

	// Don't know what this was...
	return nil, fault.ErrInvalidArgument
}

// sshKey is the private implementation satisfying Key.
type sshKey struct {
	unsafe    bool
	signer    ssh.Signer
	publicKey ssh.PublicKey
}

func (k *sshKey) Fingerprint() string {
	return ssh.FingerprintSHA256(k.publicKey)
}

func (k *sshKey) PublicKey() ssh.PublicKey {
	return k.publicKey
}

func (k *sshKey) Signer() ssh.Signer {
	return k.signer
}
