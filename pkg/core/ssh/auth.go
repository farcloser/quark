package ssh

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/core/filesystem"
)

type signingKey struct {
	Signer    ssh.Signer
	PublicKey ssh.PublicKey
}

// GetAuthMethod returns an AuthMethod usable (honoring the openssh resolution logic wrt explicit keys, agent,
// and identities).
// Specifying useConfig will additionally use ~/.ssh/config for host and config resolution.
//
//revive:disable:cognitive-complexity
//revive:disable:flag-parameter
func GetAuthMethod(explicitKeys []*Key, endpointString string, withSSHConfig bool) (ssh.AuthMethod, error) {
	var err error

	// Get config IdentitiesOnly
	identityOnly := !withSSHConfig || ssh_config.Get(endpointString, "IdentitiesOnly") == "yes"

	// Get all explicitly provided keys
	keys := explicitKeys

	// Get config identities
	var identityFiles []string
	if withSSHConfig {
		identityFiles = ssh_config.GetAll(endpointString, "IdentityFile")
	}

	// If identityOnly is NOT specified, we are ALSO going to consider default files
	if !identityOnly {
		identityFiles = append(identityFiles, []string{
			"~/.ssh/id_rsa",
			"~/.ssh/id_ecdsa",
			"~/.ssh/id_ecdsa_sk",
			"~/.ssh/id_ed25519",
			"~/.ssh/id_ed25519_sk",
		}...)
	}

	var usableKeys []*signingKey

	// Process our explicitly provided keys
	for _, key := range keys {
		var signer ssh.Signer

		// Try to parse it as a private key first, with or without passphrase.
		if len(key.Passphrase) > 0 {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key.Bytes, key.Passphrase)
		} else {
			signer, err = ssh.ParsePrivateKey(key.Bytes)
		}

		// Unencrypted or successfully decrypted, we can use that as a signer.
		if err == nil {
			usableKeys = append(usableKeys, &signingKey{
				Signer:    signer,
				PublicKey: signer.PublicKey(),
			})

			continue
		}

		// Encrypted?
		// Then just get the pub part.
		var passphraseErr *ssh.PassphraseMissingError
		if errors.As(err, &passphraseErr) {
			usableKeys = append(usableKeys, &signingKey{
				PublicKey: passphraseErr.PublicKey,
			})

			continue
		}

		// Hail mary. Try to parse as a pub key
		pubKey, err := ssh.ParsePublicKey(key.Bytes)
		if err == nil {
			// Keep it then
			usableKeys = append(usableKeys, &signingKey{
				PublicKey: pubKey,
			})

			continue
		}

		// Yep...
		slog.Warn("unrecognized key format", "err", err)
	}

	// Now, load the bytes from all identityFiles.
	for _, identityFile := range identityFiles {
		// Expand the path
		if strings.HasPrefix(identityFile, "~/") {
			identityFile = filepath.Join(filesystem.HomeDir(), identityFile[2:])
		}

		// #nosec G304 -- identityFile comes from SSH config
		keyBytes, err := os.ReadFile(identityFile)
		if err != nil {
			slog.Warn("failed loading identity file", "file", identityFile, "err", err)

			continue
		}

		// Try to parse it as a private key
		_, err = ssh.ParsePrivateKey(keyBytes)
		// Unencrypted? We do not accept that. Bad opsec.
		if err == nil {
			slog.Error(
				"BAD: on-disk identity file without a passphrase - refusing to use - you need to act on it NOW.",
				"file",
				identityFile,
			)

			continue
		}

		// Encrypted? Just get the pub part.
		var passphraseErr *ssh.PassphraseMissingError
		if errors.As(err, &passphraseErr) {
			usableKeys = append(usableKeys, &signingKey{
				PublicKey: passphraseErr.PublicKey,
			})

			continue
		}

		// Hail mary. Try to parse as a pub key
		pubKey, err := ssh.ParsePublicKey(keyBytes)
		if err == nil {
			// Keep it then
			usableKeys = append(usableKeys, &signingKey{
				PublicKey: pubKey,
			})

			continue
		}

		// Any other error, invalid key somehow (or unable to read, etc).
		slog.Warn("unrecognized key format", "err", err)
	}

	// Now, get all agent known keys
	loadedSigners, err := GetAgent().Signers()
	if err != nil {
		slog.Warn("Failed to get agent signers", "err", err)
	}

	// Iterate through the agent keys and split them in two groups: provided identities, and others.
	requestedSigners := []ssh.Signer{}
	otherAgentSigners := []ssh.Signer{}

	for _, agentSigner := range loadedSigners {
		found := false

		for idx, providedKey := range usableKeys {
			if ssh.FingerprintSHA256(agentSigner.PublicKey()) == ssh.FingerprintSHA256(providedKey.PublicKey) {
				// Add it to the list
				requestedSigners = append(requestedSigners, agentSigner)
				// Remove it from the usableKeys
				usableKeys = append(usableKeys[:idx], usableKeys[idx+1:]...)
				found = true

				break
			}
		}

		if !found {
			otherAgentSigners = append(otherAgentSigners, agentSigner)
		}
	}

	// No ident only means we are ALSO trying the other keys AFTER the requested ones
	if !identityOnly {
		requestedSigners = append(requestedSigners, otherAgentSigners...)
	}

	// Iterate through the remainder of provided id files and pick the ones that have an un-/de-encrypted private key.
	for _, key := range usableKeys {
		if key.Signer != nil {
			requestedSigners = append(requestedSigners, key.Signer)
		} else {
			slog.Warn("key ignored (encrypted, no passphrase provided, not found in agent)", "key", key.PublicKey)
		}
	}

	// Return the signers auth
	return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		return requestedSigners, nil
	}), nil
}
