package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"

	"github.com/farcloser/quark/pkg/fault"
)

// KeyPair represents a generated cosign key pair.
type KeyPair struct {
	// PrivateKey is the PEM-encoded private key (encrypted if password provided).
	PrivateKey []byte

	// PublicKey is the PEM-encoded public key.
	PublicKey []byte
}

// GenerateKeyPair generates an ECDSA P-256 key pair compatible with cosign.
// If password is provided, the private key will be encrypted using scrypt + nacl secretbox
// (matching Cosign's encryption format).
func GenerateKeyPair(password []byte) *KeyPair {
	// Generate ECDSA P-256 key (cosign default).
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Errorf("%w: %w", fault.ErrSystemFailure, err))
	}

	// Encode public key.
	publicKeyPEM := marshalPublicKey(&privateKey.PublicKey)

	// Encode private key.
	var privateKeyPEM []byte

	if len(password) > 0 {
		privateKeyPEM = encryptPrivateKey(privateKey, password)
	} else {
		privateKeyPEM = marshalPrivateKey(privateKey)
	}

	return &KeyPair{
		PrivateKey: privateKeyPEM,
		PublicKey:  publicKeyPEM,
	}
}

// marshalPublicKey encodes an ECDSA public key to PEM format.
func marshalPublicKey(publicKey *ecdsa.PublicKey) []byte {
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(fmt.Errorf("%w: failed to encode public key: %w", fault.ErrSystemFailure, err))
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  publicKeyPEMType,
		Bytes: derBytes,
	})
}

// marshalPrivateKey encodes an ECDSA private key to PEM format.
func marshalPrivateKey(privateKey *ecdsa.PrivateKey) []byte {
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(fmt.Errorf("%w: failed to marshal private key: %w", fault.ErrSystemFailure, err))
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  privateKeyPEMType,
		Bytes: derBytes,
	})
}

// encryptPrivateKey encrypts a private key using cosign's format (scrypt + nacl secretbox).
func encryptPrivateKey(privateKey *ecdsa.PrivateKey, password []byte) []byte {
	// Marshal private key to DER.
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(fmt.Errorf("%w: failed to marshal private key: %w", fault.ErrSystemFailure, err))
	}

	// Derive key using scrypt (cosign uses N=32768, r=8, p=1).
	const (
		scryptN       = 32768
		scryptR       = 8
		scryptP       = 1
		scryptKeyLen  = 32
		scryptSaltLen = 32
	)

	// Generate salt for scrypt.
	salt := make([]byte, scryptSaltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Errorf("%w: failed to generate salt: %w", fault.ErrSystemFailure, err))
	}

	key, err := scrypt.Key(password, salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		panic(fmt.Errorf("%w: failed to derive key: %w", fault.ErrSystemFailure, err))
	}

	// Generate nonce for secretbox.
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(fmt.Errorf("%w: failed to generate nonce: %w", fault.ErrSystemFailure, err))
	}

	// Encrypt using nacl secretbox.
	var secretKey [32]byte

	copy(secretKey[:], key)

	encrypted := secretbox.Seal(nil, derBytes, &nonce, &secretKey)

	// Build the encrypted PEM block with cosign headers.
	pemBlock := &pem.Block{
		Type: "ENCRYPTED SIGSTORE PRIVATE KEY",
		Headers: map[string]string{
			"kdf":   "scrypt",
			"salt":  base64.StdEncoding.EncodeToString(salt),
			"nonce": base64.StdEncoding.EncodeToString(nonce[:]),
		},
		Bytes: encrypted,
	}

	return pem.EncodeToMemory(pemBlock)
}
