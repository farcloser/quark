// Package cosign provides cosign/crane test utilities for signing and attesting images.
package cosign

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/farcloser/quark/testutil/registry"
)

const (
	cosignBinary = "cosign"
	craneBinary  = "crane"
	fileMode     = 0o600
	flagKey      = "--key"
	flagBundle   = "--bundle"

	errMsgCreateTempDir = "creating temp dir: %w"
)

// KeyPair holds paths to a cosign key pair.
type KeyPair struct {
	PrivateKey string
	PublicKey  string
	Password   string
	dir        string
}

// GenerateKeyPair creates a new cosign key pair in a temp directory.
// Caller must call Cleanup() when done.
func GenerateKeyPair(password string) (*KeyPair, error) {
	dir, err := os.MkdirTemp("", "cosign-test-*")
	if err != nil {
		return nil, fmt.Errorf(errMsgCreateTempDir, err)
	}

	keyPair := &KeyPair{
		PrivateKey: filepath.Join(dir, "cosign.key"),
		PublicKey:  filepath.Join(dir, "cosign.pub"),
		Password:   password,
		dir:        dir,
	}

	//nolint:gosec // Test utility intentionally executes cosign CLI.
	cmd := exec.CommandContext(context.Background(), cosignBinary, "generate-key-pair",
		"--output-key-prefix", filepath.Join(dir, "cosign"))

	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD="+password)

	output, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.RemoveAll(dir)

		return nil, fmt.Errorf("cosign generate-key-pair: %w: %s", err, output)
	}

	return keyPair, nil
}

// Cleanup removes the temporary directory containing the key pair.
func (keyPair *KeyPair) Cleanup() {
	if keyPair.dir != "" {
		_ = os.RemoveAll(keyPair.dir)
	}
}

// ReadPublicKey returns the public key bytes.
func (keyPair *KeyPair) ReadPublicKey() ([]byte, error) {
	data, err := os.ReadFile(keyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}

	return data, nil
}

// SignedImage holds a signed OCI image reference and its signature.
type SignedImage struct {
	// ImageRef is the full image reference with digest (e.g., ttl.sh/test@sha256:...).
	ImageRef string
	// Digest is just the digest part (e.g., sha256:...).
	Digest string
	// Bundle is the signature layer content.
	// For new format: sigstore bundle JSON.
	// For legacy format: simple signing payload JSON.
	Bundle []byte
	// Annotations contains layer annotations (only populated for legacy format).
	Annotations map[string]string
	// MediaType is the media type of the signature layer.
	MediaType string
}

// Annotation keys used by legacy cosign signatures.
const (
	AnnotationSignature = "dev.cosignproject.cosign/signature"
)

// SignImage pushes a test image to a local registry, signs it with new bundle format,
// and returns the signature. If uploadToRekor is true, the signature is uploaded
// to the Rekor transparency log.
func SignImage(keyPair *KeyPair, uploadToRekor bool) (*SignedImage, error) {
	return signImageInternal(keyPair, false, uploadToRekor)
}

// SignImageLegacy pushes a test image to a local registry, signs it with legacy format
// (simple signing payload + annotations), and returns the signature.
// Does not upload to Rekor.
func SignImageLegacy(keyPair *KeyPair) (*SignedImage, error) {
	return signImageInternal(keyPair, true, false)
}

func signImageInternal(keyPair *KeyPair, legacy, uploadToRekor bool) (*SignedImage, error) {
	// Get shared registry.
	reg, err := registry.EnsureContainerRegistry()
	if err != nil {
		return nil, fmt.Errorf("starting registry: %w", err)
	}

	registryAddr := reg.Address

	dir, err := os.MkdirTemp("", "cosign-image-*")
	if err != nil {
		return nil, fmt.Errorf(errMsgCreateTempDir, err)
	}

	defer os.RemoveAll(dir)

	// Create a minimal layer.
	layerPath := filepath.Join(dir, "layer.tar")

	if err := createMinimalLayer(layerPath); err != nil {
		return nil, err
	}

	// Generate unique image tag using the local registry.
	imageTag := fmt.Sprintf("%s/cosign-test-%s:latest", registryAddr, uniqueID())

	// Push image using crane (insecure for local registry).
	imageRef, err := pushImage(layerPath, imageTag, true)
	if err != nil {
		return nil, err
	}

	// Sign the image.
	if legacy {
		if err := signImageLegacyWithCosign(keyPair, imageRef); err != nil {
			return nil, err
		}
	} else {
		if err := signImageWithCosign(keyPair, imageRef, dir, uploadToRekor); err != nil {
			return nil, err
		}
	}

	// Fetch the signature.
	payload, annotations, mediaType, err := fetchSignature(imageRef, legacy)
	if err != nil {
		return nil, err
	}

	// Extract digest from image ref.
	idx := findSubstring(imageRef, "@")
	digest := ""
	if idx >= 0 {
		digest = imageRef[idx+1:]
	}

	return &SignedImage{
		ImageRef:    imageRef,
		Digest:      digest,
		Bundle:      payload,
		Annotations: annotations,
		MediaType:   mediaType,
	}, nil
}

// signImageWithCosign signs an image using cosign with new bundle format.
func signImageWithCosign(keyPair *KeyPair, imageRef, dir string, uploadToRekor bool) error {
	args := []string{"sign", flagKey, keyPair.PrivateKey, "--allow-insecure-registry"}

	if !uploadToRekor {
		signingConfig, err := createNoTlogSigningConfig(dir)
		if err != nil {
			return err
		}

		args = append(args, "--signing-config", signingConfig)
	}

	args = append(args, "--yes", imageRef)

	//nolint:gosec // Test utility.
	cmd := exec.CommandContext(context.Background(), cosignBinary, args...)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD="+keyPair.Password)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cosign sign: %w: %s", err, output)
	}

	return nil
}

// signImageLegacyWithCosign signs an image using cosign with legacy format.
func signImageLegacyWithCosign(keyPair *KeyPair, imageRef string) error {
	//nolint:gosec // Test utility.
	cmd := exec.CommandContext(context.Background(), cosignBinary, "sign",
		flagKey, keyPair.PrivateKey,
		"--allow-insecure-registry",
		"--new-bundle-format=false",
		"--use-signing-config=false",
		"--tlog-upload=false",
		"--yes",
		imageRef)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD="+keyPair.Password)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cosign sign legacy: %w: %s", err, output)
	}

	return nil
}

// fetchSignature fetches the signature for a signed image.
// Returns the payload bytes, annotations, and media type.
// Handles both legacy (.sig tag) and modern (referrers) formats.
func fetchSignature(imageRef string, legacy bool) ([]byte, map[string]string, string, error) {
	idx := findSubstring(imageRef, "@sha256:")
	if idx < 0 {
		return nil, nil, "", fmt.Errorf("invalid image ref: %s", imageRef)
	}

	imageDigest := imageRef[idx+1:]
	imageRepo := imageRef[:idx]

	// Get signature tag - legacy uses .sig suffix, modern uses referrers tag without suffix.
	var sigTag string
	if legacy {
		sigTag = fmt.Sprintf("%s:sha256-%s.sig", imageRepo, imageDigest[7:])
	} else {
		sigTag = fmt.Sprintf("%s:sha256-%s", imageRepo, imageDigest[7:])
	}

	//nolint:gosec // Test utility.
	cmd := exec.CommandContext(context.Background(), craneBinary, "manifest", "--insecure", sigTag)

	manifestOutput, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, "", fmt.Errorf("crane manifest: %w: %s", err, manifestOutput)
	}

	// For modern format, this is an OCI index - need to resolve to the actual manifest.
	if !legacy {
		var index struct {
			Manifests []struct {
				Digest string `json:"digest"`
			} `json:"manifests"`
		}
		if err := json.Unmarshal(manifestOutput, &index); err != nil {
			return nil, nil, "", fmt.Errorf("parsing index: %w", err)
		}

		if len(index.Manifests) == 0 {
			return nil, nil, "", fmt.Errorf("no manifests in index")
		}

		// Fetch the actual signature manifest.
		manifestRef := fmt.Sprintf("%s@%s", imageRepo, index.Manifests[0].Digest)

		//nolint:gosec // Test utility.
		cmd = exec.CommandContext(context.Background(), craneBinary, "manifest", "--insecure", manifestRef)

		manifestOutput, err = cmd.CombinedOutput()
		if err != nil {
			return nil, nil, "", fmt.Errorf("crane manifest (inner): %w: %s", err, manifestOutput)
		}
	}

	// Parse manifest to find signature layer.
	var manifest struct {
		Layers []struct {
			Digest      string            `json:"digest"`
			MediaType   string            `json:"mediaType"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
		Annotations map[string]string `json:"annotations"`
	}

	if err := json.Unmarshal(manifestOutput, &manifest); err != nil {
		return nil, nil, "", fmt.Errorf("parsing manifest: %w", err)
	}

	if len(manifest.Layers) == 0 {
		return nil, nil, "", fmt.Errorf("no layers found in signature manifest")
	}

	layer := manifest.Layers[0]

	// Fetch the layer content.
	blobRef := fmt.Sprintf("%s@%s", imageRepo, layer.Digest)

	//nolint:gosec // Test utility.
	cmd = exec.CommandContext(context.Background(), craneBinary, "blob", "--insecure", blobRef)

	payload, err := cmd.Output()
	if err != nil {
		return nil, nil, "", fmt.Errorf("crane blob: %w", err)
	}

	// For legacy, annotations are on the layer. For modern, on the manifest.
	annotations := layer.Annotations
	if !legacy && len(manifest.Annotations) > 0 {
		annotations = manifest.Annotations
	}

	return payload, annotations, layer.MediaType, nil
}

// AttestedImage holds an attested OCI image reference and its attestation.
type AttestedImage struct {
	// ImageRef is the full image reference with digest (e.g., ttl.sh/test@sha256:...).
	ImageRef string
	// Digest is just the digest part (e.g., sha256:...).
	Digest string
	// Bundle is the attestation layer content.
	Bundle []byte
	// Annotations contains layer annotations.
	Annotations map[string]string
	// MediaType is the media type of the attestation layer.
	MediaType string
}

// AttestImage pushes a test image to a local registry, attests it with new bundle format,
// and returns the attestation. If uploadToRekor is true, the attestation is uploaded
// to the Rekor transparency log.
func AttestImage(keyPair *KeyPair, predicateType string, predicate []byte, uploadToRekor bool) (*AttestedImage, error) {
	return attestImageInternal(keyPair, predicateType, predicate, false, uploadToRekor)
}

// AttestImageLegacy pushes a test image to a local registry, attests it with legacy format,
// and returns the attestation. Does not upload to Rekor.
func AttestImageLegacy(keyPair *KeyPair, predicateType string, predicate []byte) (*AttestedImage, error) {
	return attestImageInternal(keyPair, predicateType, predicate, true, false)
}

func attestImageInternal(keyPair *KeyPair, predicateType string, predicate []byte, legacy, uploadToRekor bool) (*AttestedImage, error) {
	// Get shared registry.
	reg, err := registry.EnsureContainerRegistry()
	if err != nil {
		return nil, fmt.Errorf("starting registry: %w", err)
	}

	registryAddr := reg.Address

	dir, err := os.MkdirTemp("", "cosign-attest-*")
	if err != nil {
		return nil, fmt.Errorf(errMsgCreateTempDir, err)
	}

	defer os.RemoveAll(dir)

	// Create a minimal layer.
	layerPath := filepath.Join(dir, "layer.tar")

	if err := createMinimalLayer(layerPath); err != nil {
		return nil, err
	}

	// Generate unique image tag using the local registry.
	imageTag := fmt.Sprintf("%s/cosign-test-%s:latest", registryAddr, uniqueID())

	// Push image using crane (insecure for local registry).
	imageRef, err := pushImage(layerPath, imageTag, true)
	if err != nil {
		return nil, err
	}

	// Write predicate to file.
	predicatePath := filepath.Join(dir, "predicate.json")
	if err := os.WriteFile(predicatePath, predicate, fileMode); err != nil {
		return nil, fmt.Errorf("writing predicate: %w", err)
	}

	// Attest the image.
	if legacy {
		if err := attestImageLegacyWithCosign(keyPair, imageRef, predicateType, predicatePath); err != nil {
			return nil, err
		}
	} else {
		if err := attestImageWithCosign(keyPair, imageRef, predicateType, predicatePath, dir, uploadToRekor); err != nil {
			return nil, err
		}
	}

	// Fetch the attestation.
	bundle, annotations, mediaType, err := fetchAttestation(imageRef, legacy)
	if err != nil {
		return nil, err
	}

	// Extract digest from image ref.
	idx := findSubstring(imageRef, "@")
	digest := ""
	if idx >= 0 {
		digest = imageRef[idx+1:]
	}

	return &AttestedImage{
		ImageRef:    imageRef,
		Digest:      digest,
		Bundle:      bundle,
		Annotations: annotations,
		MediaType:   mediaType,
	}, nil
}

// attestImageWithCosign attests an image using cosign with new bundle format.
func attestImageWithCosign(keyPair *KeyPair, imageRef, predicateType, predicatePath, dir string, uploadToRekor bool) error {
	args := []string{"attest", flagKey, keyPair.PrivateKey, "--allow-insecure-registry", "--predicate", predicatePath, "--type", predicateType}

	if !uploadToRekor {
		signingConfig, err := createNoTlogSigningConfig(dir)
		if err != nil {
			return err
		}

		args = append(args, "--signing-config", signingConfig)
	}

	args = append(args, "--yes", imageRef)

	//nolint:gosec // Test utility.
	cmd := exec.CommandContext(context.Background(), cosignBinary, args...)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD="+keyPair.Password)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cosign attest: %w: %s", err, output)
	}

	return nil
}

// attestImageLegacyWithCosign attests an image using cosign with legacy format.
func attestImageLegacyWithCosign(keyPair *KeyPair, imageRef, predicateType, predicatePath string) error {
	//nolint:gosec // Test utility.
	cmd := exec.CommandContext(context.Background(), cosignBinary, "attest",
		flagKey, keyPair.PrivateKey,
		"--allow-insecure-registry",
		"--predicate", predicatePath,
		"--type", predicateType,
		"--new-bundle-format=false",
		"--use-signing-config=false",
		"--tlog-upload=false",
		"--yes",
		imageRef)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD="+keyPair.Password)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cosign attest legacy: %w: %s", err, output)
	}

	return nil
}

// fetchAttestation fetches the attestation for an attested image.
// Returns the bundle bytes, annotations, and media type.
// Handles both legacy (.att tag) and modern (referrers) formats.
func fetchAttestation(imageRef string, legacy bool) ([]byte, map[string]string, string, error) {
	idx := findSubstring(imageRef, "@sha256:")
	if idx < 0 {
		return nil, nil, "", fmt.Errorf("invalid image ref: %s", imageRef)
	}

	imageDigest := imageRef[idx+1:]
	imageRepo := imageRef[:idx]

	// Get attestation tag - legacy uses .att suffix, modern uses referrers tag without suffix.
	var attTag string
	if legacy {
		attTag = fmt.Sprintf("%s:sha256-%s.att", imageRepo, imageDigest[7:])
	} else {
		attTag = fmt.Sprintf("%s:sha256-%s", imageRepo, imageDigest[7:])
	}

	//nolint:gosec // Test utility.
	cmd := exec.CommandContext(context.Background(), craneBinary, "manifest", "--insecure", attTag)

	manifestOutput, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, "", fmt.Errorf("crane manifest: %w: %s", err, manifestOutput)
	}

	// For modern format, this is an OCI index - need to resolve to the actual manifest.
	if !legacy {
		var index struct {
			Manifests []struct {
				Digest string `json:"digest"`
			} `json:"manifests"`
		}
		if err := json.Unmarshal(manifestOutput, &index); err != nil {
			return nil, nil, "", fmt.Errorf("parsing index: %w", err)
		}

		if len(index.Manifests) == 0 {
			return nil, nil, "", fmt.Errorf("no manifests in index")
		}

		// Fetch the actual attestation manifest.
		manifestRef := fmt.Sprintf("%s@%s", imageRepo, index.Manifests[0].Digest)

		//nolint:gosec // Test utility.
		cmd = exec.CommandContext(context.Background(), craneBinary, "manifest", "--insecure", manifestRef)

		manifestOutput, err = cmd.CombinedOutput()
		if err != nil {
			return nil, nil, "", fmt.Errorf("crane manifest (inner): %w: %s", err, manifestOutput)
		}
	}

	// Parse manifest to find attestation layer.
	var manifest struct {
		Layers []struct {
			Digest      string            `json:"digest"`
			MediaType   string            `json:"mediaType"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
		Annotations map[string]string `json:"annotations"`
	}

	if err := json.Unmarshal(manifestOutput, &manifest); err != nil {
		return nil, nil, "", fmt.Errorf("parsing manifest: %w", err)
	}

	if len(manifest.Layers) == 0 {
		return nil, nil, "", fmt.Errorf("no layers found in attestation manifest")
	}

	layer := manifest.Layers[0]

	// Fetch the layer content.
	blobRef := fmt.Sprintf("%s@%s", imageRepo, layer.Digest)

	//nolint:gosec // Test utility.
	cmd = exec.CommandContext(context.Background(), craneBinary, "blob", "--insecure", blobRef)

	bundle, err := cmd.Output()
	if err != nil {
		return nil, nil, "", fmt.Errorf("crane blob: %w", err)
	}

	// For legacy, annotations are on the layer. For modern, on the manifest.
	annotations := layer.Annotations
	if !legacy && len(manifest.Annotations) > 0 {
		annotations = manifest.Annotations
	}

	return bundle, annotations, layer.MediaType, nil
}

// createNoTlogSigningConfig creates a signing config file without Rekor transparency log.
func createNoTlogSigningConfig(dir string) (string, error) {
	config := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
	}

	configPath := filepath.Join(dir, "signing-config.json")

	data, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("marshaling signing config: %w", err)
	}

	if err := os.WriteFile(configPath, data, fileMode); err != nil {
		return "", fmt.Errorf("writing signing config: %w", err)
	}

	return configPath, nil
}

// createMinimalLayer creates a minimal tar layer for testing.
func createMinimalLayer(path string) error {
	dir := filepath.Dir(path)
	testFile := filepath.Join(dir, "testfile")

	if err := os.WriteFile(testFile, []byte("test content\n"), fileMode); err != nil {
		return fmt.Errorf("writing test file: %w", err)
	}

	//nolint:gosec // Test utility.
	cmd := exec.CommandContext(context.Background(), "tar", "-cvf", path, "-C", dir, "testfile")

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("creating tar: %w: %s", err, output)
	}

	return nil
}

// pushImage pushes an image layer to the registry and returns the full reference with digest.
// If insecure is true, uses --insecure flag for HTTP registry.
func pushImage(layerPath, imageTag string, insecure bool) (string, error) {
	args := []string{"append", "-f", layerPath, "-t", imageTag}
	if insecure {
		args = append(args, "--insecure")
	}

	//nolint:gosec // Test utility.
	cmd := exec.CommandContext(context.Background(), craneBinary, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("crane append: %w: %s", err, output)
	}

	// Parse output to get the full reference with digest.
	lines := string(output)
	for _, line := range splitLines(lines) {
		if idx := findSubstring(line, "@sha256:"); idx >= 0 {
			return line, nil
		}
	}

	return "", fmt.Errorf("failed to parse crane output: %s", output)
}

func splitLines(s string) []string {
	var lines []string

	start := 0

	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}

	if start < len(s) {
		lines = append(lines, s[start:])
	}

	return lines
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}

	return -1
}

var (
	idCounter int64
	idPrefix  = generatePrefix()
)

func generatePrefix() string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(err)
	}

	return hex.EncodeToString(buf[:])
}

func uniqueID() string {
	idCounter++

	return fmt.Sprintf("%s-%d", idPrefix, idCounter)
}
