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
// (matching cosign's encryption format).
func GenerateKeyPair(password []byte) (*KeyPair, error) {
	// Generate ECDSA P-256 key (cosign default).
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyGeneration, err)
	}

	// Encode public key.
	publicKeyPEM, err := marshalPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	// Encode private key.
	var privateKeyPEM []byte

	if len(password) > 0 {
		privateKeyPEM, err = encryptPrivateKey(privateKey, password)
		if err != nil {
			return nil, err
		}
	} else {
		privateKeyPEM, err = marshalPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
	}

	return &KeyPair{
		PrivateKey: privateKeyPEM,
		PublicKey:  publicKeyPEM,
	}, nil
}

// marshalPublicKey encodes an ECDSA public key to PEM format.
func marshalPublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to encode public key: %w", ErrKeyGeneration, err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}), nil
}

// marshalPrivateKey encodes an ECDSA private key to PEM format.
func marshalPrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal private key: %w", ErrKeyGeneration, err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}), nil
}

// encryptPrivateKey encrypts a private key using cosign's format (scrypt + nacl secretbox).
func encryptPrivateKey(privateKey *ecdsa.PrivateKey, password []byte) ([]byte, error) {
	// Marshal private key to DER.
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal private key: %w", ErrKeyEncryption, err)
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
		return nil, fmt.Errorf("%w: failed to generate salt: %w", ErrKeyEncryption, err)
	}

	key, err := scrypt.Key(password, salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to derive key: %w", ErrKeyEncryption, err)
	}

	// Generate nonce for secretbox.
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("%w: failed to generate nonce: %w", ErrKeyEncryption, err)
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

	return pem.EncodeToMemory(pemBlock), nil
}
