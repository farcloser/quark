# Media types in OCI and hierachy

```
  OCI Index (MediaTypeOCIIndex / MediaTypeDockerIndex)
  │
  ├── Manifests: []Descriptor (PLURAL)
  │
  │   ┌─────────────────────────────────────────────────────────────────────────
  │   │ CONTAINER IMAGE
  │   └─────────────────────────────────────────────────────────────────────────
  │   ├── → Manifest (MediaTypeOCIManifest / MediaTypeDockerManifest)
  │   │   ├── Config (SINGULAR)
  │   │   │   └── → (MediaTypeOCIConfig / MediaTypeDockerConfig)
  │   │   ├── Layers (PLURAL, ordered)
  │   │   │   ├── → (MediaTypeOCILayer)
  │   │   │   ├── → (MediaTypeOCILayerZstd)
  │   │   │   ├── → (MediaTypeOCILayerUncompressed)
  │   │   │   ├── → (MediaTypeDockerLayer)
  │   │   │   └── → (MediaTypeDockerLayerUncompressed)
  │   │   └── Subject (OPTIONAL)
  │
  │   ┌─────────────────────────────────────────────────────────────────────────
  │   │ SIGNATURE (attached via Subject)
  │   └─────────────────────────────────────────────────────────────────────────
  │   ├── → Manifest (MediaTypeOCIManifest)
  │   │   ├── Config (SINGULAR)
  │   │   │   └── → (MediaTypeOCIEmptyJSON)
  │   │   ├── Layers (PLURAL, typically 1)
  │   │   │   └── → (MediaTypeCosignSignature)
  │   │   └── Subject → points to signed manifest
  │
  │   ┌─────────────────────────────────────────────────────────────────────────
  │   │ ATTESTATION (attached via Subject)
  │   └─────────────────────────────────────────────────────────────────────────
  │   ├── → Manifest (MediaTypeOCIManifest)
  │   │   ├── Config (SINGULAR)
  │   │   │   └── → (MediaTypeOCIEmptyJSON)
  │   │   ├── Layers (PLURAL, typically 1)
  │   │   │   └── → (MediaTypeDSSEEnvelope)
  │   │   │       └── [INSIDE BLOB]: payloadType = (PayloadTypeInToto)
  │   │   └── Subject → points to attested manifest
  │
  │   ┌─────────────────────────────────────────────────────────────────────────
  │   │ SBOM (attached via Subject)
  │   └─────────────────────────────────────────────────────────────────────────
  │   └── → Manifest (MediaTypeOCIManifest)
  │       ├── Config (SINGULAR)
  │       │   └── → (MediaTypeOCIEmptyJSON)
  │       ├── Layers (PLURAL, typically 1)
  │       │   └── → (MediaTypeCycloneDXJSON)
  │       └── Subject → points to described manifest


  NOT IN REGISTRY:
  └── MediaTypeOCILayout - only in local OCI tarball (oci-layout file)

```
