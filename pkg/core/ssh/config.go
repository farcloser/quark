package ssh

import (
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/core/network"
)

// GetClientConfig returns an ssh config.
func GetClientConfig(keys []*Key, endpoint *Endpoint, withSSHConfig bool) (*ssh.ClientConfig, error) {
	// Get auth methods
	authMethod, err := GetAuthMethod(keys, endpoint.Host, withSSHConfig)
	if err != nil {
		return nil, err
	}

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
