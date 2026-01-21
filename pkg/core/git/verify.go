package git

import (
	"fmt"
	"io"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/fault"
)

// SignatureInfo contains information about a commit signature.
type SignatureInfo struct {
	// KeyFingerprint is the SHA256 fingerprint of the signing key.
	KeyFingerprint string
	// KeyType is the key algorithm (e.g., "ssh-ed25519", "ssh-rsa").
	KeyType string
}

// IsSigned verifies if a given commit is signed or not.
func (r *Repo) IsSigned(hash string) (bool, error) {
	plumbingHash := plumbing.NewHash(hash)

	commit, err := r.repo.CommitObject(plumbingHash)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrSignatureNoSuchCommit, err)
	}

	// Note: git-go has ssh signatures in there.
	if commit.PGPSignature == "" {
		return false, nil
	}

	return true, nil
}

// GetCommitSigner returns the verified signature info for the requested commit.
func (r *Repo) GetCommitSigner(hash string) (sigInfo *SignatureInfo, err error) {
	plumbingHash := plumbing.NewHash(hash)

	commit, err := r.repo.CommitObject(plumbingHash)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureNoSuchCommit, err)
	}

	// Note: git-go has ssh signatures in there.
	if commit.PGPSignature == "" {
		return nil, ErrSignatureMissing
	}

	// Parse the SSH signature.
	sigData, err := dearmorSSHSignature(commit.PGPSignature)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureInvalidFormat, err)
	}

	// Extract public key from signature.
	pubKey, namespace, sigBlob, err := parseSSHSignatureBlob(sigData)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureInvalidFormat, err)
	}

	if namespace != sshSigNamespace {
		return nil, fmt.Errorf("%w: unexpected namespace %q", ErrSignatureInvalidFormat, namespace)
	}

	sigInfo = &SignatureInfo{
		KeyFingerprint: ssh.FingerprintSHA256(pubKey),
		KeyType:        pubKey.Type(),
	}

	// Build the signed data from commit content.
	// The commit content is everything except the signature itself.
	commitContent, err := buildCommitContent(commit)
	if err != nil {
		return nil, err
	}

	signedData := buildSSHSignedData(sshSigNamespace, sshSigHashAlgo, commitContent)

	// Verify the signature.
	if err := pubKey.Verify(signedData, sigBlob); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureVerificationFailed, err)
	}

	return sigInfo, nil
}

// buildCommitContent builds the commit content that was signed.
// Uses go-git's EncodeWithoutSignature to get the exact bytes that were signed.
func buildCommitContent(commit *object.Commit) ([]byte, error) {
	obj := &plumbing.MemoryObject{}
	if err := commit.EncodeWithoutSignature(obj); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureCommitError, err)
	}

	reader, err := obj.Reader()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	defer reader.Close()

	by, err := io.ReadAll(reader)
	if err != nil {
		err = fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	return by, err
}
