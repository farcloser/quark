package sshprime

import (
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/fault"
)

func (key *Key) getSigner() (ssh.Signer, error) {
	var (
		signer ssh.Signer
		err    error
	)

	if len(key.Passphrase) > 0 {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key.Bytes, key.Passphrase)
	} else {
		signer, err = ssh.ParsePrivateKey(key.Bytes)
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrInvalidArgument, err)
	}

	return signer, nil
}
