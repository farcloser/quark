package sshprime

import (
	"golang.org/x/crypto/ssh"
)

// Endpoint represents an ssh host along with a username.
type Endpoint struct {
	User string
	Host string
	Port int
}

// Key represents a parsed SSH key.
// If the key is a private key, and we were able to decrypt it, it has a non nil signer.
// Public keys, or keys we were not able to decrypt only have a PublicKey and of course a Fingerprint().
type Key interface {
	PublicKey() ssh.PublicKey
	Fingerprint() string
	Signer() ssh.Signer
}
