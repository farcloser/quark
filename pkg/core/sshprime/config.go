package sshprime

import (
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/core/network"
)

// GetClientConfig returns an ssh config.
// Note: we can't seal the implementation because go-git (or others) do depend on raw ClientConfig...
func GetClientConfig(keys []Key, endpoint *Endpoint, withSSHConfig bool) (*ssh.ClientConfig, error) {
	// Get auth methods
	signers := GetSigners(keys, endpoint.Host, withSSHConfig)
	authMethod := ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		return signers, nil
	})

	// Get fingerprint verifier
	// Use known_hosts verification otherwise
	hostKeyCallback, err := GetFingerprinter().GetVerifier(withSSHConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigInvalid, err)
	}

	// Create SSH client config
	return &ssh.ClientConfig{
		Config: network.DefaultSSHConfig,
		User:   endpoint.User,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: network.DefaultSSHHostKeyAlgorithms,
		Timeout:           network.DefaultSSHConnectionTimeout,
	}, nil
}
