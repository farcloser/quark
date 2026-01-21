package trust_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"

	"github.com/farcloser/quark/pkg/core/trust"
)

func TestGenerateKeyPair_NoPassword(t *testing.T) {
	t.Parallel()

	kp := trust.GenerateKeyPair(nil)

	if len(kp.PublicKey) == 0 {
		t.Fatal("PublicKey should not be empty")
	}

	if len(kp.PrivateKey) == 0 {
		t.Fatal("PrivateKey should not be empty")
	}

	// Verify public key is valid PEM and parseable
	pubBlock, _ := pem.Decode(kp.PublicKey)
	if pubBlock == nil {
		t.Fatal("failed to decode public key PEM")
	}

	if pubBlock.Type != "PUBLIC KEY" {
		t.Errorf("expected public key PEM type 'PUBLIC KEY', got %q", pubBlock.Type)
	}

	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}

	if ecPub.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}

	// Verify private key is valid unencrypted PEM and parseable
	privBlock, _ := pem.Decode(kp.PrivateKey)
	if privBlock == nil {
		t.Fatal("failed to decode private key PEM")
	}

	if privBlock.Type != "PRIVATE KEY" {
		t.Errorf("expected private key PEM type 'PRIVATE KEY', got %q", privBlock.Type)
	}

	priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	ecPriv, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", priv)
	}

	// Verify public key matches private key
	if !ecPub.Equal(&ecPriv.PublicKey) {
		t.Error("public key does not match private key")
	}
}

func TestGenerateKeyPair_EmptyPassword(t *testing.T) {
	t.Parallel()

	// Empty byte slice should behave same as nil (no encryption)
	kp := trust.GenerateKeyPair([]byte{})

	privBlock, _ := pem.Decode(kp.PrivateKey)
	if privBlock == nil {
		t.Fatal("failed to decode private key PEM")
	}

	if privBlock.Type != "PRIVATE KEY" {
		t.Errorf("expected unencrypted 'PRIVATE KEY', got %q", privBlock.Type)
	}
}

func TestGenerateKeyPair_WithPassword(t *testing.T) {
	t.Parallel()

	password := []byte("test-password-123")
	kp := trust.GenerateKeyPair(password)

	if len(kp.PublicKey) == 0 {
		t.Fatal("PublicKey should not be empty")
	}

	if len(kp.PrivateKey) == 0 {
		t.Fatal("PrivateKey should not be empty")
	}

	// Verify public key is still valid and parseable
	pubBlock, _ := pem.Decode(kp.PublicKey)
	if pubBlock == nil {
		t.Fatal("failed to decode public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}

	if ecPub.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}

	// Verify private key is encrypted with cosign format
	privBlock, _ := pem.Decode(kp.PrivateKey)
	if privBlock == nil {
		t.Fatal("failed to decode private key PEM")
	}

	if privBlock.Type != "ENCRYPTED SIGSTORE PRIVATE KEY" {
		t.Errorf("expected encrypted PEM type 'ENCRYPTED SIGSTORE PRIVATE KEY', got %q", privBlock.Type)
	}

	// Verify cosign-compatible headers
	if kdf, ok := privBlock.Headers["kdf"]; !ok || kdf != "scrypt" {
		t.Errorf("expected kdf header 'scrypt', got %q", kdf)
	}

	salt, ok := privBlock.Headers["salt"]
	if !ok {
		t.Fatal("missing salt header")
	}

	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		t.Fatalf("failed to decode salt: %v", err)
	}

	if len(saltBytes) != 32 {
		t.Errorf("expected 32-byte salt, got %d bytes", len(saltBytes))
	}

	nonce, ok := privBlock.Headers["nonce"]
	if !ok {
		t.Fatal("missing nonce header")
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		t.Fatalf("failed to decode nonce: %v", err)
	}

	if len(nonceBytes) != 24 {
		t.Errorf("expected 24-byte nonce, got %d bytes", len(nonceBytes))
	}

	// Encrypted bytes should not be empty
	if len(privBlock.Bytes) == 0 {
		t.Error("encrypted private key bytes should not be empty")
	}
}

func TestGenerateKeyPair_DifferentPasswords_DifferentOutput(t *testing.T) {
	t.Parallel()

	kp1 := trust.GenerateKeyPair([]byte("password1"))
	kp2 := trust.GenerateKeyPair([]byte("password2"))

	// Different passwords should produce different encrypted output
	// (due to different random salt/nonce)
	if string(kp1.PrivateKey) == string(kp2.PrivateKey) {
		t.Error("different passwords should produce different encrypted keys")
	}
}

func TestGenerateKeyPair_Uniqueness(t *testing.T) {
	t.Parallel()

	kp1 := trust.GenerateKeyPair(nil)
	kp2 := trust.GenerateKeyPair(nil)

	// Each call should generate a different key pair
	if string(kp1.PublicKey) == string(kp2.PublicKey) {
		t.Error("subsequent calls should generate different key pairs")
	}

	if string(kp1.PrivateKey) == string(kp2.PrivateKey) {
		t.Error("subsequent calls should generate different key pairs")
	}
}

// INTENTION: Encrypted private key should be decryptable with correct password
// and the decrypted key should match the public key.
func TestGenerateKeyPair_DecryptionRoundTrip(t *testing.T) {
	t.Parallel()

	password := []byte("test-password-roundtrip")
	kp := trust.GenerateKeyPair(password)

	// Parse the public key for later comparison
	pubBlock, _ := pem.Decode(kp.PublicKey)
	if pubBlock == nil {
		t.Fatal("failed to decode public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}

	// Parse the encrypted private key
	privBlock, _ := pem.Decode(kp.PrivateKey)
	if privBlock == nil {
		t.Fatal("failed to decode private key PEM")
	}

	// Extract salt and nonce from headers
	saltB64, ok := privBlock.Headers["salt"]
	if !ok {
		t.Fatal("missing salt header")
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		t.Fatalf("failed to decode salt: %v", err)
	}

	nonceB64, ok := privBlock.Headers["nonce"]
	if !ok {
		t.Fatal("missing nonce header")
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		t.Fatalf("failed to decode nonce: %v", err)
	}

	var nonce [24]byte
	copy(nonce[:], nonceBytes)

	// Derive key using scrypt with same parameters as encryption
	const (
		scryptN      = 32768
		scryptR      = 8
		scryptP      = 1
		scryptKeyLen = 32
	)

	key, err := scrypt.Key(password, salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		t.Fatalf("failed to derive key: %v", err)
	}

	var secretKey [32]byte
	copy(secretKey[:], key)

	// Decrypt using nacl secretbox
	decrypted, ok := secretbox.Open(nil, privBlock.Bytes, &nonce, &secretKey)
	if !ok {
		t.Fatal("failed to decrypt private key - secretbox.Open returned false")
	}

	// Parse the decrypted private key
	priv, err := x509.ParsePKCS8PrivateKey(decrypted)
	if err != nil {
		t.Fatalf("failed to parse decrypted private key: %v", err)
	}

	ecPriv, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", priv)
	}

	// Verify the decrypted private key's public key matches the original public key
	if !ecPub.Equal(&ecPriv.PublicKey) {
		t.Error("decrypted private key does not match public key")
	}
}

// INTENTION: Decryption with wrong password should fail.
func TestGenerateKeyPair_DecryptionWithWrongPassword(t *testing.T) {
	t.Parallel()

	password := []byte("correct-password")
	wrongPassword := []byte("wrong-password")
	kp := trust.GenerateKeyPair(password)

	// Parse the encrypted private key
	privBlock, _ := pem.Decode(kp.PrivateKey)
	if privBlock == nil {
		t.Fatal("failed to decode private key PEM")
	}

	// Extract salt and nonce
	saltB64 := privBlock.Headers["salt"]
	salt, _ := base64.StdEncoding.DecodeString(saltB64)

	nonceB64 := privBlock.Headers["nonce"]
	nonceBytes, _ := base64.StdEncoding.DecodeString(nonceB64)

	var nonce [24]byte
	copy(nonce[:], nonceBytes)

	// Derive key with WRONG password
	const (
		scryptN      = 32768
		scryptR      = 8
		scryptP      = 1
		scryptKeyLen = 32
	)

	key, err := scrypt.Key(wrongPassword, salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		t.Fatalf("failed to derive key: %v", err)
	}

	var secretKey [32]byte
	copy(secretKey[:], key)

	// Attempt to decrypt - should fail
	_, ok := secretbox.Open(nil, privBlock.Bytes, &nonce, &secretKey)
	if ok {
		t.Error("decryption with wrong password should fail")
	}
}
