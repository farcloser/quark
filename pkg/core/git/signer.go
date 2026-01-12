package git

import (
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"

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
