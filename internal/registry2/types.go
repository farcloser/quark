package registry2

import (
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"

	"github.com/farcloser/quark/dev/fault"
	quarktypes "github.com/farcloser/quark/internal/types"
)

// ConfigFile is the image configuration blob with runtime metadata.
// See: https://github.com/opencontainers/image-spec/blob/master/config.md
type ConfigFile = v1.ConfigFile

// Content holds raw manifest/index bytes and its digest.
// Used for reading/writing manifests and indexes without parsing.
// This preserves digests during copy operations.
type Content struct {
	raw    []byte
	digest quarktypes.Digest
}

// NewContent creates a Content from raw bytes.
// If digest is empty, it is computed from raw.
func NewContent(raw []byte, dig quarktypes.Digest) *Content {
	if dig == "" {
		dig = digest.FromBytes(raw)
	}

	return &Content{raw: raw, digest: dig}
}

// Digest returns the content digest.
func (c *Content) Digest() quarktypes.Digest {
	return c.digest
}

// RawManifest returns the raw bytes.
// Implements remote.Taggable for pushing to registries.
func (c *Content) RawManifest() ([]byte, error) {
	return c.raw, nil
}

// ParseManifest parses Content as a Manifest.
func (c *Content) ParseManifest() (*Manifest, error) {
	var manifest Manifest
	if err := json.Unmarshal(c.raw, &manifest); err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrInvalidJSON, err)
	}

	return &manifest, nil
}

// ParseIndex parses Content as an Index.
func (c *Content) ParseIndex() (*Index, error) {
	var index Index
	if err := json.Unmarshal(c.raw, &index); err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrInvalidJSON, err)
	}

	return &index, nil
}

// Descriptor points to content in a registry: mediaType + size + digest.
// Used in manifests and indexes to reference layers, configs, and child manifests.
type Descriptor struct {
	Size         int64             `json:"size"`
	Digest       quarktypes.Digest `json:"digest"`
	URLs         []string          `json:"urls,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Data         string            `json:"data,omitempty"`
	ArtifactType ArtifactType      `json:"artifactType,omitempty"`

	// Only on []Manifests or Config
	MediaType MediaType `json:"mediaType"`
	// Only on []Manifests
	Platform *quarktypes.Platform `json:"platform,omitempty"`
}

// Manifest describes a single-platform container image.
// Contains a config descriptor and ordered layer descriptors.
type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     MediaType         `json:"mediaType,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
	Subject       *Descriptor       `json:"subject,omitempty"`
	ArtifactType  ArtifactType      `json:"artifactType,omitempty"`
	Config        Descriptor        `json:"config"`
	Layers        []*Descriptor     `json:"layers"`
}

// Index describes a multi-platform image (manifest list).
// Contains descriptors pointing to platform-specific manifests.
type Index struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     MediaType         `json:"mediaType,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
	Subject       *Descriptor       `json:"subject,omitempty"`
	ArtifactType  ArtifactType      `json:"artifactType,omitempty"`
	Manifests     []*Descriptor     `json:"manifests"`
}

// ToContent serializes a Manifest to Content.
func (m *Manifest) ToContent() (*Content, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize manifest: %w", err)
	}

	return NewContent(raw, ""), nil
}

// ToContent serializes an Index to Content.
func (idx *Index) ToContent() (*Content, error) {
	raw, err := json.Marshal(idx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize index: %w", err)
	}

	return NewContent(raw, ""), nil
}
