package registry2_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	"gotest.tools/v3/assert"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/internal/registry2"
	"github.com/farcloser/quark/internal/types"
	testreg "github.com/farcloser/quark/testutil/registry"
)

// testRegistry wraps InMemoryRegistry with helper methods for testing.
type testRegistry struct {
	reg *testreg.InMemoryRegistry
}

// newTestRegistry creates a new in-memory OCI registry for testing.
func newTestRegistry(t *testing.T) *testRegistry {
	t.Helper()

	return &testRegistry{
		reg: testreg.EnsureInMemoryRegistry(t),
	}
}

// image creates a types.Image pointing to this test registry.
func (tr *testRegistry) image(path, tag string) *types.Image {
	return &types.Image{
		Registry: &types.RegistryCredentials{
			Domain: tr.reg.Address,
		},
		Path: path,
		Tag:  tag,
	}
}

// imageWithDigest creates a types.Image with a specific digest.
func (tr *testRegistry) imageWithDigest(path string, dgst types.Digest) *types.Image {
	return &types.Image{
		Registry: &types.RegistryCredentials{
			Domain: tr.reg.Address,
		},
		Path:   path,
		Digest: dgst,
	}
}

// pushBlob pushes a blob to the registry and returns its digest.
func (tr *testRegistry) pushBlob(
	t *testing.T,
	client registry2.Client,
	path string,
	content []byte,
) types.Digest {
	t.Helper()

	img := tr.image(path, "")
	dgst := computeDigest(content)

	err := client.WriteBlob(context.Background(), img, dgst, int64(len(content)), bytes.NewReader(content))
	assert.NilError(t, err)

	return dgst
}

// pushManifest pushes a manifest to the registry.
func (tr *testRegistry) pushManifest(
	t *testing.T,
	client registry2.Client,
	path, tag string,
	content *registry2.Content,
) types.Digest {
	t.Helper()

	img := tr.image(path, tag)

	dgst, err := client.WriteManifest(context.Background(), img, content)
	assert.NilError(t, err)

	return dgst
}

// createMinimalManifest creates a minimal OCI manifest for testing.
func createMinimalManifest(configDigest, layerDigest types.Digest) *registry2.Content {
	manifest := registry2.Manifest{
		SchemaVersion: 2,
		MediaType:     registry2.MediaTypeOCIManifest,
		Config: registry2.Descriptor{
			MediaType: registry2.MediaTypeOCIConfig,
			Size:      2,
			Digest:    configDigest,
		},
		Layers: []*registry2.Descriptor{
			{
				MediaType: registry2.MediaTypeOCILayer,
				Size:      5,
				Digest:    layerDigest,
			},
		},
	}

	raw, _ := json.Marshal(manifest) //nolint:errchkjson // test helper, struct is known-valid

	return registry2.NewContent(raw, "")
}

// createMinimalIndex creates a minimal OCI index for testing.
func createMinimalIndex(manifestDigest types.Digest) *registry2.Content {
	index := registry2.Index{
		SchemaVersion: 2,
		MediaType:     registry2.MediaTypeOCIIndex,
		Manifests: []*registry2.Descriptor{
			{
				MediaType: registry2.MediaTypeOCIManifest,
				Size:      100,
				Digest:    manifestDigest,
				Platform: &types.Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			},
		},
	}

	raw, _ := json.Marshal(index) //nolint:errchkjson // test helper, struct is known-valid

	return registry2.NewContent(raw, "")
}

// computeDigest computes the SHA256 digest of content.
func computeDigest(content []byte) types.Digest {
	h := sha256.Sum256(content)

	return digest.NewDigestFromBytes(digest.SHA256, h[:])
}

// =============================================================================
// Content/Digest Sanity Tests
// =============================================================================

func TestContent_DigestMatchesBytes(t *testing.T) {
	t.Parallel()

	// Verify that NewContent computes correct digest
	raw := []byte(`{"schemaVersion":2}`)
	content := registry2.NewContent(raw, "")

	expected := computeDigest(raw)
	assert.Equal(t, expected, content.Digest())
}

func TestManifest_RoundTrip(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Create manifest with known content
	manifest := registry2.Manifest{
		SchemaVersion: 2,
		MediaType:     registry2.MediaTypeOCIManifest,
		Config: registry2.Descriptor{
			MediaType: registry2.MediaTypeOCIConfig,
			Size:      2,
			Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
		Layers: []*registry2.Descriptor{},
	}

	raw, err := json.Marshal(manifest)
	assert.NilError(t, err)

	originalDigest := computeDigest(raw)
	t.Logf("Original bytes: %s", raw)
	t.Logf("Original digest: %s", originalDigest)

	content := registry2.NewContent(raw, "")
	assert.Equal(t, originalDigest, content.Digest())

	// Push to registry
	img := tr.image("test/repo", "v1.0")
	returnedDigest, err := client.WriteManifest(context.Background(), img, content)
	assert.NilError(t, err)
	t.Logf("WriteManifest returned: %s", returnedDigest)

	// Digests should match
	assert.Equal(t, originalDigest, returnedDigest)
}

func TestManifest_RegistryPreservesBytes(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Create manifest with known content
	manifest := registry2.Manifest{
		SchemaVersion: 2,
		MediaType:     registry2.MediaTypeOCIManifest,
		Config: registry2.Descriptor{
			MediaType: registry2.MediaTypeOCIConfig,
			Size:      2,
			Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
		Layers: []*registry2.Descriptor{},
	}

	raw, _ := json.Marshal(manifest)
	originalDigest := computeDigest(raw)
	content := registry2.NewContent(raw, "")

	// Push
	img := tr.image("test/repo", "v1.0")
	_, err := client.WriteManifest(context.Background(), img, content)
	assert.NilError(t, err)

	// Fetch back using go-containerregistry directly (bypass our cache)
	// to verify registry preserves bytes
	imgWithDigest := tr.imageWithDigest("test/repo", originalDigest)
	resolvedDigest, err := client.ResolveDigest(context.Background(), img)
	assert.NilError(t, err)
	t.Logf("ResolveDigest returned: %s", resolvedDigest)
	t.Logf("Original digest: %s", originalDigest)
	assert.Equal(t, originalDigest, resolvedDigest)

	// The digests match, so registry stored our exact bytes
	// Now try ReadManifest
	readContent, err := client.ReadManifest(context.Background(), imgWithDigest)
	if err != nil {
		t.Logf("ReadManifest error: %v", err)
		t.Logf("Cache key would be: %s", imgWithDigest.Digest.Encoded())
		t.FailNow()
	}

	readRaw, _ := readContent.RawManifest()
	t.Logf("Read bytes: %s", readRaw)
	assert.Assert(t, bytes.Equal(raw, readRaw), "bytes should match")
}

// =============================================================================
// Ping Tests
// =============================================================================

func TestPing_Success(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()
	img := tr.image("test/repo", "latest")

	err := client.Ping(context.Background(), img)
	assert.NilError(t, err)
}

func TestPing_InvalidRegistry(t *testing.T) {
	t.Parallel()

	client := registry2.NewClient()
	img := &types.Image{
		Registry: &types.RegistryCredentials{
			Domain: "localhost:1", // Invalid port, nothing listening.
		},
		Path: "test/repo",
	}

	err := client.Ping(context.Background(), img)
	assert.Assert(t, err != nil)
}

func TestPing_ContextCancelled(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()
	img := tr.image("test/repo", "latest")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := client.Ping(ctx, img)
	assert.Assert(t, errors.Is(err, context.Canceled))
}

// =============================================================================
// ResolveDigest Tests
// =============================================================================

func TestResolveDigest_ExistingTag(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push a blob and manifest first.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest := createMinimalManifest(configDigest, layerDigest)
	tr.pushManifest(t, client, "test/repo", "v1.0", manifest)

	// Resolve the tag.
	img := tr.image("test/repo", "v1.0")

	resolvedDigest, err := client.ResolveDigest(context.Background(), img)

	assert.NilError(t, err)
	assert.Assert(t, resolvedDigest != "")
	assert.Assert(t, strings.HasPrefix(resolvedDigest.String(), "sha256:"))
}

func TestResolveDigest_NonExistentTag(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()
	img := tr.image("test/repo", "nonexistent")

	_, err := client.ResolveDigest(context.Background(), img)
	assert.Assert(t, errors.Is(err, fault.ErrNotFound))
}

func TestResolveDigest_NonExistentRepository(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()
	img := tr.image("nonexistent/repo", "latest")

	_, err := client.ResolveDigest(context.Background(), img)
	assert.Assert(t, errors.Is(err, fault.ErrNotFound))
}

func TestResolveDigest_WithExistingDigest(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push content.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest := createMinimalManifest(configDigest, layerDigest)
	manifestDigest := tr.pushManifest(t, client, "test/repo", "v1.0", manifest)

	// Resolve by digest (should validate and return same digest).
	img := tr.imageWithDigest("test/repo", manifestDigest)

	resolvedDigest, err := client.ResolveDigest(context.Background(), img)

	assert.NilError(t, err)
	assert.Equal(t, manifestDigest, resolvedDigest)
}

func TestResolveDigest_WithNonExistentDigest(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	fakeDigest := digest.FromString("nonexistent")
	img := tr.imageWithDigest("test/repo", fakeDigest)

	_, err := client.ResolveDigest(context.Background(), img)
	assert.Assert(t, errors.Is(err, fault.ErrNotFound))
}

func TestResolveDigest_ContextCancelled(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()
	img := tr.image("test/repo", "latest")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.ResolveDigest(ctx, img)
	assert.Assert(t, errors.Is(err, context.Canceled))
}

// =============================================================================
// ListTags Tests
// =============================================================================

func TestListTags_EmptyRepository(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()
	img := tr.image("test/repo", "")

	tags, err := client.ListTags(context.Background(), img)

	// Empty repo may return empty list or not found depending on implementation.
	if err != nil {
		assert.Assert(t, errors.Is(err, fault.ErrNotFound))
	} else {
		assert.Equal(t, 0, len(tags))
	}
}

func TestListTags_SingleTag(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push content with a tag.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest := createMinimalManifest(configDigest, layerDigest)
	tr.pushManifest(t, client, "test/repo", "v1.0", manifest)

	// List tags.
	img := tr.image("test/repo", "")

	tags, err := client.ListTags(context.Background(), img)

	assert.NilError(t, err)
	assert.Equal(t, 1, len(tags))
	assert.Equal(t, "v1.0", tags[0])
}

func TestListTags_MultipleTags(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push content.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest := createMinimalManifest(configDigest, layerDigest)

	// Push same manifest with multiple tags.
	tr.pushManifest(t, client, "test/repo", "v1.0", manifest)
	tr.pushManifest(t, client, "test/repo", "v1.1", manifest)
	tr.pushManifest(t, client, "test/repo", "latest", manifest)

	// List tags.
	img := tr.image("test/repo", "")

	tags, err := client.ListTags(context.Background(), img)

	assert.NilError(t, err)
	assert.Equal(t, 3, len(tags))
}

func TestListTags_ContextCancelled(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()
	img := tr.image("test/repo", "")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.ListTags(ctx, img)
	assert.Assert(t, errors.Is(err, context.Canceled))
}

// =============================================================================
// ReadManifest Tests
// =============================================================================

func TestReadManifest_ExistingManifest(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push content.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest := createMinimalManifest(configDigest, layerDigest)
	manifestDigest := tr.pushManifest(t, client, "test/repo", "v1.0", manifest)

	// Read manifest by digest.
	img := tr.imageWithDigest("test/repo", manifestDigest)

	content, err := client.ReadManifest(context.Background(), img)

	assert.NilError(t, err)
	assert.Assert(t, content != nil)

	// Parse and verify.
	parsed, err := content.ParseManifest()
	assert.NilError(t, err)
	assert.Equal(t, 2, parsed.SchemaVersion)
	assert.Equal(t, configDigest, parsed.Config.Digest)
	assert.Equal(t, 1, len(parsed.Layers))
}

func TestReadManifest_ExistingIndex(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push a manifest first.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest := createMinimalManifest(configDigest, layerDigest)
	manifestDigest := tr.pushManifest(t, client, "test/repo", "v1.0-amd64", manifest)

	// Push an index referencing the manifest.
	index := createMinimalIndex(manifestDigest)
	indexDigest := tr.pushManifest(t, client, "test/repo", "v1.0", index)

	// Read index by digest.
	img := tr.imageWithDigest("test/repo", indexDigest)

	content, err := client.ReadManifest(context.Background(), img)

	assert.NilError(t, err)
	assert.Assert(t, content != nil)

	// Parse and verify.
	parsed, err := content.ParseIndex()
	assert.NilError(t, err)
	assert.Equal(t, 2, parsed.SchemaVersion)
	assert.Equal(t, 1, len(parsed.Manifests))
	assert.Equal(t, manifestDigest, parsed.Manifests[0].Digest)
}

func TestReadManifest_ByDigest(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push content.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest := createMinimalManifest(configDigest, layerDigest)
	manifestDigest := tr.pushManifest(t, client, "test/repo", "v1.0", manifest)

	// Read by digest.
	img := tr.imageWithDigest("test/repo", manifestDigest)

	content, err := client.ReadManifest(context.Background(), img)

	assert.NilError(t, err)
	assert.Assert(t, content != nil)
}

func TestReadManifest_RequiresDigest(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()
	img := tr.image("test/repo", "sometag") // tag only, no digest

	_, err := client.ReadManifest(context.Background(), img)
	assert.Assert(t, errors.Is(err, fault.ErrInvalidArgument))
}

func TestReadManifest_NonExistentDigest(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	fakeDigest := digest.FromString("nonexistent")
	img := tr.imageWithDigest("test/repo", fakeDigest)

	_, err := client.ReadManifest(context.Background(), img)
	assert.Assert(t, errors.Is(err, fault.ErrNotFound))
}

func TestReadManifest_ContextCancelled(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	fakeDigest := digest.FromString("test")
	img := tr.imageWithDigest("test/repo", fakeDigest)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.ReadManifest(ctx, img)
	assert.Assert(t, errors.Is(err, context.Canceled))
}

// =============================================================================
// ReadBlob Tests
// =============================================================================

func TestReadBlob_ExistingBlob(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push a blob.
	content := []byte("hello world blob content")
	blobDigest := tr.pushBlob(t, client, "test/repo", content)

	// Read it back.
	img := tr.image("test/repo", "")

	reader, err := client.ReadBlob(context.Background(), img, blobDigest)
	assert.NilError(t, err)

	defer reader.Close()

	readContent, err := io.ReadAll(reader)
	assert.NilError(t, err)
	assert.DeepEqual(t, content, readContent)
}

func TestReadBlob_NonExistentBlob(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	fakeDigest := digest.FromString("nonexistent")
	img := tr.image("test/repo", "")

	_, err := client.ReadBlob(context.Background(), img, fakeDigest)
	assert.Assert(t, errors.Is(err, fault.ErrNotFound))
}

func TestReadBlob_EmptyBlob(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push empty blob.
	content := []byte{}
	blobDigest := tr.pushBlob(t, client, "test/repo", content)

	// Read it back.
	img := tr.image("test/repo", "")

	reader, err := client.ReadBlob(context.Background(), img, blobDigest)
	assert.NilError(t, err)

	defer reader.Close()

	readContent, err := io.ReadAll(reader)
	assert.NilError(t, err)
	assert.Equal(t, 0, len(readContent))
}

func TestReadBlob_LargeBlob(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push large blob (1MB).
	content := make([]byte, 1024*1024)
	for idx := range content {
		content[idx] = byte(idx % 256)
	}

	blobDigest := tr.pushBlob(t, client, "test/repo", content)

	// Read it back.
	img := tr.image("test/repo", "")

	reader, err := client.ReadBlob(context.Background(), img, blobDigest)
	assert.NilError(t, err)

	defer reader.Close()

	readContent, err := io.ReadAll(reader)
	assert.NilError(t, err)
	assert.DeepEqual(t, content, readContent)
}

func TestReadBlob_ContextCancelled(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	fakeDigest := digest.FromString("test")
	img := tr.image("test/repo", "")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.ReadBlob(ctx, img, fakeDigest)
	assert.Assert(t, errors.Is(err, context.Canceled))
}

// =============================================================================
// WriteManifest Tests
// =============================================================================

func TestWriteManifest_NewManifest(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push blobs first.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	// Create and push manifest.
	manifest := createMinimalManifest(configDigest, layerDigest)
	img := tr.image("test/repo", "v1.0")

	returnedDigest, err := client.WriteManifest(context.Background(), img, manifest)

	assert.NilError(t, err)
	assert.Assert(t, returnedDigest != "")

	// Verify it's readable (ReadManifest requires digest).
	imgWithDigest := tr.imageWithDigest("test/repo", returnedDigest)
	readContent, err := client.ReadManifest(context.Background(), imgWithDigest)
	assert.NilError(t, err)
	parsed, err := readContent.ParseManifest()
	assert.NilError(t, err)
	assert.Assert(t, parsed.MediaType.IsImage())
}

func TestWriteManifest_NewIndex(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push a manifest first.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest := createMinimalManifest(configDigest, layerDigest)
	manifestDigest := tr.pushManifest(t, client, "test/repo", "v1.0-amd64", manifest)

	// Push index.
	index := createMinimalIndex(manifestDigest)
	img := tr.image("test/repo", "v1.0")

	returnedDigest, err := client.WriteManifest(context.Background(), img, index)

	assert.NilError(t, err)
	assert.Assert(t, returnedDigest != "")

	// Verify it's readable as index (by digest).
	imgWithDigest := tr.imageWithDigest("test/repo", returnedDigest)
	readContent, err := client.ReadManifest(context.Background(), imgWithDigest)
	assert.NilError(t, err)
	parsedIndex, err := readContent.ParseIndex()
	assert.NilError(t, err)
	assert.Assert(t, parsedIndex.MediaType.IsIndex())
}

func TestWriteManifest_OverwriteTag(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push initial manifest.
	configContent := []byte("{}")
	layerContent := []byte("layer1")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest1 := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest1 := createMinimalManifest(configDigest, layerDigest1)
	digest1 := tr.pushManifest(t, client, "test/repo", "latest", manifest1)

	// Push different manifest to same tag.
	layerContent2 := []byte("layer2 different")
	layerDigest2 := tr.pushBlob(t, client, "test/repo", layerContent2)

	manifest2 := createMinimalManifest(configDigest, layerDigest2)
	img := tr.image("test/repo", "latest")

	digest2, err := client.WriteManifest(context.Background(), img, manifest2)

	assert.NilError(t, err)
	assert.Assert(t, digest1 != digest2) // Different content, different digest.

	// Verify tag points to new manifest (read by digest).
	imgWithDigest := tr.imageWithDigest("test/repo", digest2)
	readContent, err := client.ReadManifest(context.Background(), imgWithDigest)
	assert.NilError(t, err)

	parsed, err := readContent.ParseManifest()
	assert.NilError(t, err)
	assert.Equal(t, layerDigest2, parsed.Layers[0].Digest)
}

func TestWriteManifest_WithoutTag(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push blobs.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	// Push manifest without tag (by digest only).
	manifest := createMinimalManifest(configDigest, layerDigest)
	img := tr.image("test/repo", "") // No tag.

	returnedDigest, err := client.WriteManifest(context.Background(), img, manifest)

	assert.NilError(t, err)
	assert.Assert(t, returnedDigest != "")

	// Verify readable by digest.
	imgByDigest := tr.imageWithDigest("test/repo", returnedDigest)

	readContent, err := client.ReadManifest(context.Background(), imgByDigest)
	assert.NilError(t, err)
	parsedManifest, err := readContent.ParseManifest()
	assert.NilError(t, err)
	assert.Assert(t, parsedManifest.MediaType.IsImage())
}

func TestWriteManifest_ContextCancelled(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	manifest := createMinimalManifest(
		digest.FromString("config"),
		digest.FromString("layer"),
	)
	img := tr.image("test/repo", "v1.0")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.WriteManifest(ctx, img, manifest)
	assert.Assert(t, errors.Is(err, context.Canceled))
}

// =============================================================================
// WriteBlob Tests
// =============================================================================

func TestWriteBlob_NewBlob(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	content := []byte("hello world")
	img := tr.image("test/repo", "")
	expectedDigest := computeDigest(content)

	err := client.WriteBlob(context.Background(), img, expectedDigest, int64(len(content)), bytes.NewReader(content))

	assert.NilError(t, err)

	// Verify readable.
	reader, err := client.ReadBlob(context.Background(), img, expectedDigest)
	assert.NilError(t, err)

	defer reader.Close()

	readContent, err := io.ReadAll(reader)
	assert.NilError(t, err)
	assert.DeepEqual(t, content, readContent)
}

func TestWriteBlob_EmptyBlob(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	content := []byte{}
	img := tr.image("test/repo", "")
	dgst := computeDigest(content)

	err := client.WriteBlob(context.Background(), img, dgst, int64(len(content)), bytes.NewReader(content))

	assert.NilError(t, err)
}

func TestWriteBlob_LargeBlob(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// 5MB blob.
	content := make([]byte, 5*1024*1024)
	for idx := range content {
		content[idx] = byte(idx % 256)
	}

	img := tr.image("test/repo", "")
	dgst := computeDigest(content)

	err := client.WriteBlob(context.Background(), img, dgst, int64(len(content)), bytes.NewReader(content))

	assert.NilError(t, err)

	// Verify readable.
	reader, err := client.ReadBlob(context.Background(), img, dgst)
	assert.NilError(t, err)

	defer reader.Close()

	readContent, err := io.ReadAll(reader)
	assert.NilError(t, err)
	assert.Equal(t, len(content), len(readContent))
}

func TestWriteBlob_DuplicateBlob(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	content := []byte("duplicate content")
	img := tr.image("test/repo", "")
	dgst := computeDigest(content)

	// Push same content twice - should succeed (idempotent).
	err := client.WriteBlob(context.Background(), img, dgst, int64(len(content)), bytes.NewReader(content))
	assert.NilError(t, err)

	err = client.WriteBlob(context.Background(), img, dgst, int64(len(content)), bytes.NewReader(content))
	assert.NilError(t, err)
}

func TestWriteBlob_ContextCancelled(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	content := []byte("test")
	img := tr.image("test/repo", "")
	dgst := computeDigest(content)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := client.WriteBlob(ctx, img, dgst, int64(len(content)), bytes.NewReader(content))
	assert.Assert(t, errors.Is(err, context.Canceled))
}

// =============================================================================
// DeleteManifest Tests
// =============================================================================

func TestDeleteManifest_ByTag(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push content.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest := createMinimalManifest(configDigest, layerDigest)
	tr.pushManifest(t, client, "test/repo", "v1.0", manifest)

	// Delete by tag.
	img := tr.image("test/repo", "v1.0")

	err := client.DeleteManifest(context.Background(), img)

	assert.NilError(t, err)

	// Verify tag no longer exists.
	_, err = client.ResolveDigest(context.Background(), img)
	assert.Assert(t, errors.Is(err, fault.ErrNotFound))
}

func TestDeleteManifest_ByDigest(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push content.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest := createMinimalManifest(configDigest, layerDigest)
	manifestDigest := tr.pushManifest(t, client, "test/repo", "v1.0", manifest)

	// Delete by digest.
	img := tr.imageWithDigest("test/repo", manifestDigest)

	err := client.DeleteManifest(context.Background(), img)

	assert.NilError(t, err)

	// Verify manifest no longer exists in registry.
	// Note: ReadManifest may return cached data, so we use ResolveDigest
	// which queries the registry directly.
	_, err = client.ResolveDigest(context.Background(), img)
	assert.Assert(t, errors.Is(err, fault.ErrNotFound))
}

func TestDeleteManifest_NonExistent(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()
	img := tr.image("test/repo", "nonexistent")

	err := client.DeleteManifest(context.Background(), img)

	// Should return not found error.
	assert.Assert(t, errors.Is(err, fault.ErrNotFound))
}

func TestDeleteManifest_PreservesOtherTags(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push content with multiple tags.
	configContent := []byte("{}")
	layerContent := []byte("layer")
	configDigest := tr.pushBlob(t, client, "test/repo", configContent)
	layerDigest := tr.pushBlob(t, client, "test/repo", layerContent)

	manifest := createMinimalManifest(configDigest, layerDigest)
	tr.pushManifest(t, client, "test/repo", "v1.0", manifest)
	tr.pushManifest(t, client, "test/repo", "latest", manifest)

	// Delete one tag.
	img := tr.image("test/repo", "v1.0")

	err := client.DeleteManifest(context.Background(), img)
	assert.NilError(t, err)

	// Other tag should still exist.
	imgLatest := tr.image("test/repo", "latest")

	_, err = client.ResolveDigest(context.Background(), imgLatest)
	assert.NilError(t, err)
}

func TestDeleteManifest_RequiresTagOrDigest(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()
	img := tr.image("test/repo", "") // No tag or digest

	err := client.DeleteManifest(context.Background(), img)

	assert.Assert(t, errors.Is(err, fault.ErrInvalidArgument))
}

func TestDeleteManifest_ContextCancelled(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()
	img := tr.image("test/repo", "v1.0")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := client.DeleteManifest(ctx, img)
	assert.Assert(t, errors.Is(err, context.Canceled))
}

// =============================================================================
// SignatureImage and AttestationImage Helper Tests
// =============================================================================

func TestSignatureImage(t *testing.T) {
	t.Parallel()

	img := &types.Image{
		Registry: &types.RegistryCredentials{
			Domain: "registry.example.com",
		},
		Path:   "myrepo/myimage",
		Tag:    "v1.0",
		Digest: "sha256:abc123def456",
	}

	sigImg := registry2.SignatureImage(img)

	assert.Equal(t, img.Registry, sigImg.Registry)
	assert.Equal(t, img.Path, sigImg.Path)
	assert.Equal(t, "sha256-abc123def456.sig", sigImg.Tag)
	assert.Equal(t, types.Digest(""), sigImg.Digest) // Digest should not be copied.
}

func TestAttestationImage(t *testing.T) {
	t.Parallel()

	img := &types.Image{
		Registry: &types.RegistryCredentials{
			Domain: "registry.example.com",
		},
		Path:   "myrepo/myimage",
		Tag:    "v1.0",
		Digest: "sha256:abc123def456",
	}

	attImg := registry2.AttestationImage(img)

	assert.Equal(t, img.Registry, attImg.Registry)
	assert.Equal(t, img.Path, attImg.Path)
	assert.Equal(t, "sha256-abc123def456.att", attImg.Tag)
	assert.Equal(t, types.Digest(""), attImg.Digest) // Digest should not be copied.
}

// =============================================================================
// Integration Tests - Full Workflows
// =============================================================================

func TestIntegration_PushAndPullImage(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push config blob.
	configContent := []byte(`{"architecture":"amd64","os":"linux"}`)
	configDigest := computeDigest(configContent)

	err := client.WriteBlob(
		context.Background(),
		tr.image("myapp", ""),
		configDigest,
		int64(len(configContent)),
		bytes.NewReader(configContent),
	)
	assert.NilError(t, err)

	// Push layer blob.
	layerContent := []byte("layer data representing filesystem")
	layerDigest := computeDigest(layerContent)

	err = client.WriteBlob(
		context.Background(),
		tr.image("myapp", ""),
		layerDigest,
		int64(len(layerContent)),
		bytes.NewReader(layerContent),
	)
	assert.NilError(t, err)

	// Create and push manifest.
	manifest := &registry2.Manifest{
		SchemaVersion: 2,
		MediaType:     registry2.MediaTypeOCIManifest,
		Config: registry2.Descriptor{
			MediaType: registry2.MediaTypeOCIConfig,
			Size:      int64(len(configContent)),
			Digest:    configDigest,
		},
		Layers: []*registry2.Descriptor{
			{
				MediaType: registry2.MediaTypeOCILayer,
				Size:      int64(len(layerContent)),
				Digest:    layerDigest,
			},
		},
	}

	manifestContent, err := manifest.ToContent()
	assert.NilError(t, err)

	img := tr.image("myapp", "v1.0.0")

	manifestDigest, err := client.WriteManifest(context.Background(), img, manifestContent)
	assert.NilError(t, err)

	// Verify we can read everything back.
	// 1. Resolve tag to digest.
	resolvedDigest, err := client.ResolveDigest(context.Background(), img)
	assert.NilError(t, err)
	assert.Equal(t, manifestDigest, resolvedDigest)

	// 2. Read manifest (requires digest).
	imgWithDigest := tr.imageWithDigest("myapp", manifestDigest)
	readManifest, err := client.ReadManifest(context.Background(), imgWithDigest)
	assert.NilError(t, err)

	parsed, err := readManifest.ParseManifest()
	assert.NilError(t, err)
	assert.Assert(t, parsed.MediaType.IsImage())
	assert.Equal(t, configDigest, parsed.Config.Digest)

	// 3. Read config blob.
	configReader, err := client.ReadBlob(context.Background(), img, configDigest)
	assert.NilError(t, err)

	defer configReader.Close()

	readConfig, err := io.ReadAll(configReader)
	assert.NilError(t, err)
	assert.DeepEqual(t, configContent, readConfig)

	// 4. Read layer blob.
	layerReader, err := client.ReadBlob(context.Background(), img, layerDigest)
	assert.NilError(t, err)

	defer layerReader.Close()

	readLayer, err := io.ReadAll(layerReader)
	assert.NilError(t, err)
	assert.DeepEqual(t, layerContent, readLayer)
}

func TestIntegration_MultiPlatformImage(t *testing.T) {
	t.Parallel()

	tr := newTestRegistry(t)
	client := registry2.NewClient()

	// Push AMD64 image.
	configAmd64 := []byte(`{"architecture":"amd64","os":"linux"}`)
	configAmd64Digest := tr.pushBlob(t, client, "myapp", configAmd64)
	layerAmd64 := []byte("amd64 layer")
	layerAmd64Digest := tr.pushBlob(t, client, "myapp", layerAmd64)

	manifestAmd64 := createMinimalManifest(configAmd64Digest, layerAmd64Digest)
	manifestAmd64Digest := tr.pushManifest(t, client, "myapp", "v1.0-amd64", manifestAmd64)

	// Push ARM64 image.
	configArm64 := []byte(`{"architecture":"arm64","os":"linux"}`)
	configArm64Digest := tr.pushBlob(t, client, "myapp", configArm64)
	layerArm64 := []byte("arm64 layer")
	layerArm64Digest := tr.pushBlob(t, client, "myapp", layerArm64)

	manifestArm64 := createMinimalManifest(configArm64Digest, layerArm64Digest)
	manifestArm64Digest := tr.pushManifest(t, client, "myapp", "v1.0-arm64", manifestArm64)

	// Create and push index.
	manifestAmd64Raw, _ := manifestAmd64.RawManifest()
	manifestArm64Raw, _ := manifestArm64.RawManifest()

	index := &registry2.Index{
		SchemaVersion: 2,
		MediaType:     registry2.MediaTypeOCIIndex,
		Manifests: []*registry2.Descriptor{
			{
				MediaType: registry2.MediaTypeOCIManifest,
				Size:      int64(len(manifestAmd64Raw)),
				Digest:    manifestAmd64Digest,
				Platform: &types.Platform{
					OS:           "linux",
					Architecture: "amd64",
				},
			},
			{
				MediaType: registry2.MediaTypeOCIManifest,
				Size:      int64(len(manifestArm64Raw)),
				Digest:    manifestArm64Digest,
				Platform: &types.Platform{
					OS:           "linux",
					Architecture: "arm64",
				},
			},
		},
	}

	indexContent, err := index.ToContent()
	assert.NilError(t, err)

	img := tr.image("myapp", "v1.0")

	indexDigest, err := client.WriteManifest(context.Background(), img, indexContent)
	assert.NilError(t, err)

	// Read index back (by digest).
	imgWithDigest := tr.imageWithDigest("myapp", indexDigest)
	readContent, err := client.ReadManifest(context.Background(), imgWithDigest)
	assert.NilError(t, err)

	parsedIndex, err := readContent.ParseIndex()
	assert.NilError(t, err)
	assert.Assert(t, parsedIndex.MediaType.IsIndex())
	assert.Equal(t, 2, len(parsedIndex.Manifests))
}

// func TestIntegration_SignatureWorkflow(t *testing.T) {
//	t.Parallel()
//
//	tr := newTestRegistry(t)
//	client := registry2.NewClient()
//
//	// Push an image.
//	configContent := []byte("{}")
//	layerContent := []byte("layer")
//	configDigest := tr.pushBlob(t, client, "myapp", configContent)
//	layerDigest := tr.pushBlob(t, client, "myapp", layerContent)
//
//	manifest := createMinimalManifest(configDigest, layerDigest)
//	img := tr.image("myapp", "v1.0")
//
//	manifestDigest, err := client.WriteManifest(context.Background(), img, manifest)
//	assert.NilError(t, err)
//
//	// Set digest on image for signature helpers.
//	img.Digest = manifestDigest
//
//	// Create signature image reference.
//	sigImg := registry2.SignatureImage(img)
//	assert.Equal(t, fmt.Sprintf("sha256-%s.sig", manifestDigest.Encoded()), sigImg.Tag)
//
//	// Push a fake signature manifest.
//	sigLayerContent := []byte(`{"critical":{"identity":{},"image":{},"type":""},"optional":{}}`)
//	sigLayerDigest := tr.pushBlob(t, client, "myapp", sigLayerContent)
//
//	sigManifest := &registry2.Manifest{
//		SchemaVersion: 2,
//		MediaType:     registry2.MediaTypeOCIManifest,
//		Config: registry2.Descriptor{
//			MediaType: registry2.MediaTypeOCIConfig,
//			Size:      2,
//			Digest:    configDigest,
//		},
//		Layers: []*registry2.Descriptor{
//			{
//				MediaType: registry2.LayerMediaTypeCosignSignature,
//				Size:      int64(len(sigLayerContent)),
//				Digest:    sigLayerDigest,
//			},
//		},
//	}
//
//	sigContent, err := sigManifest.ToContent()
//	assert.NilError(t, err)
//
//	sigDigest, err := client.WriteManifest(context.Background(), sigImg, sigContent)
//	assert.NilError(t, err)
//
//	// Read signature back (by digest).
//	sigImgWithDigest := tr.imageWithDigest("myapp", sigDigest)
//	readSig, err := client.ReadManifest(context.Background(), sigImgWithDigest)
//	assert.NilError(t, err)
//
//	parsedSig, err := readSig.ParseManifest()
//	assert.NilError(t, err)
//	assert.Assert(t, parsedSig.MediaType.IsImage())
//	assert.Equal(t, registry2.LayerMediaTypeCosignSignature, parsedSig.Layers[0].MediaType)
// }
