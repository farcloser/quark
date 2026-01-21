package sshprime

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/core/filesystem"
	netssh "github.com/farcloser/quark/pkg/core/network"
)

// GetSigners returns a list of usable signers (honoring the openssh resolution logic wrt explicit keys, agent,
// and identities).
// Specifying useConfig will additionally use ~/.ssh/config for host and config resolution.
//
//revive:disable:flag-parameter
func GetSigners(explicitKeys []Key, endpointString string, withSSHConfig bool) []ssh.Signer {
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
		identityFiles = append(identityFiles, netssh.DefaultIdentityFiles...)
	}

	// Add the keys from all provided identityFiles.
	keys = append(keys, getIdentityKeys(identityFiles)...)

	// Now, get all agent known keys
	requestedSigners, otherAgentSigners := ResolveSigners(keys)

	// If identityOnly is NOT specified, we are ALSO going to consider the other keys AFTER the requested ones
	if !identityOnly {
		requestedSigners = append(requestedSigners, otherAgentSigners...)
	}

	// Iterate through the remainder of provided id files and pick the ones that have an un-/de-encrypted private key.
	for _, key := range keys {
		if key.Signer() != nil {
			requestedSigners = append(requestedSigners, key.Signer())
		} else {
			slog.Warn("key not found in agent - and either public only or cannot decrypt - ignoring", "fingerprint", key.Fingerprint())
		}
	}

	// Return the signers auth
	return requestedSigners
}

func getIdentityKeys(identityFiles []string) []Key {
	var keys []Key

	for _, identityFile := range identityFiles {
		// Expand the path
		if strings.HasPrefix(identityFile, "~/") {
			identityFile = filepath.Join(filesystem.HomeDir(), identityFile[2:])
		}

		// #nosec G304 -- identityFile comes from SSH config and hardcoded defaults from ~/.ssh
		keyBytes, err := os.ReadFile(identityFile)
		if err != nil {
			slog.Warn("failed loading identity file", "file", identityFile, "err", err)

			continue
		}

		addedKey, err := NewKey(keyBytes, nil, true)
		if err != nil {
			slog.Error(
				"unusable key format, or on-disk identity file without a passphrase (refusing to use)",
				"file",
				identityFile,
			)

			continue
		}

		keys = append(keys, addedKey)
	}

	return keys
}

// ResolveSigners returns the list of keys from usableKeys that are known to the agent.
// If identityOnly, it will also return other agent known keys, prepended to the list.
func ResolveSigners(requestedKeys []Key) (requestedSigners, otherAgentSigners []ssh.Signer) {
	requestedSigners = []ssh.Signer{}
	otherAgentSigners = []ssh.Signer{}

	loadedSigners, err := GetAgent().Signers()
	if err != nil {
		slog.Warn("Failed to get agent signers", "err", err)
	}

	// Iterate through the agent keys and split them in two groups: provided identities, and others.
	for _, agentSigner := range loadedSigners {
		found := false

		for idx, providedKey := range requestedKeys {
			if ssh.FingerprintSHA256(agentSigner.PublicKey()) == providedKey.Fingerprint() {
				// Add it to the list
				requestedSigners = append(requestedSigners, agentSigner)
				// Remove it from the requestedKeys
				requestedKeys = append(requestedKeys[:idx], requestedKeys[idx+1:]...)
				found = true

				break
			}
		}

		if !found {
			otherAgentSigners = append(otherAgentSigners, agentSigner)
		}
	}

	return requestedSigners, otherAgentSigners
}
