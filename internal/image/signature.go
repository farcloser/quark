package image

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/farcloser/quark/internal/registry2"
	"github.com/farcloser/quark/internal/schemas"
	"github.com/farcloser/quark/internal/signature"
	"github.com/farcloser/quark/internal/types"
)

type SBOM struct {
	Annotations map[string]string
	MediaType   registry2.MediaType
	// Payload is the signature layer content.
	Payload []byte
}

/*
Legacy signature:
docker buildx imagetools inspect cgr.dev/chainguard/nginx:sha256-dad6ecc27985d8f09292bb6df5778caa001299af8f486fb023b7efda3d3f3a10.sig --raw 2>/dev/null | jq .

Layer Annotations:
dev.sigstore.cosign/chain
dev.sigstore.cosign/certificate
dev.sigstore.cosign/bundle
dev.cosignproject.cosign/signature

Layer MediaType:
application/vnd.dev.cosign.simplesigning.v1+json

Config MediaType:
application/vnd.oci.image.config.v1+json

No ArtifactType.

No Subject.

#######################
Transitional cosign:
docker buildx imagetools inspect ghcr.io/duncanite/samba@sha256:c635de11f65520f2addf951ad50fb41b6e4bcca781ca9ce147837858e2cb98bd --raw 2>/dev/null | jq .

Layer Annotations:
dev.cosignproject.cosign/signature

Layer MediaType:
application/vnd.dev.cosign.simplesigning.v1+json

Config MediaType:
application/vnd.dev.cosign.artifact.sig.v1+json

No ArtifactType.

Subject descriptor.

#######################
Attestations:

application/vnd.dsse.envelope.v1+json
*/

type Presumed string

const (
	PresumedSignature   = Presumed("signature")
	PresumedSBOM        = Presumed("sbom")
	PresumedAttestation = Presumed("attestation")
	PresumedUnknown     = Presumed("unknown")
)

// This tries to infer the type from url (for legacy type) and media-type fuzzy comparison...
func presumedType(ref string, artType string) Presumed {
	var pres Presumed

	switch registry2.ArtifactType(artType) {
	case registry2.ArtifactTypeCosignSignature:
		pres = PresumedSignature
	case registry2.ArtifactTypeCosignSBOM:
		pres = PresumedSBOM
	case registry2.ArtifactTypeCosignAttestation:
		pres = PresumedAttestation
	case registry2.ArtifactTypeSigstoreBundle:
		pres = PresumedSignature
	case registry2.ArtifactTypeDocker:
		// Could be SBOM or provenance :S. Need layer inspection to decide
		pres = PresumedUnknown
	default:
		pres = PresumedUnknown
	}

	if strings.HasSuffix(ref, ".sig") && pres != PresumedSignature {
		if pres == PresumedUnknown {
			pres = PresumedSignature
		} else {
			slog.Warn("legacy url extension seemingly disagrees with media type")
		}
	}
	if strings.HasSuffix(ref, ".att") && pres != PresumedAttestation {
		if pres == PresumedUnknown {
			pres = PresumedAttestation
		} else {
			slog.Warn("legacy url extension seemingly disagrees with media type")
		}
	}
	if strings.HasSuffix(ref, ".sbom") && pres != PresumedSBOM {
		if pres == PresumedUnknown {
			pres = PresumedSBOM
		} else {
			slog.Warn("legacy url extension seemingly disagrees with media type")
		}
	}

	if strings.Contains(string(artType), ".sig") && pres != PresumedSignature {
		if pres == PresumedUnknown {
			pres = PresumedSignature
		} else {
			slog.Warn("media type parsing disagrees")
		}

		return pres
	}

	if strings.Contains(string(artType), ".att") && pres != PresumedAttestation {
		if pres == PresumedUnknown {
			pres = PresumedAttestation
		} else {
			slog.Warn("media type parsing disagrees")
		}

		return pres
	}

	if strings.Contains(string(artType), ".sbom") && pres != PresumedSBOM {
		if pres == PresumedUnknown {
			pres = PresumedSBOM
		} else {
			slog.Warn("media type parsing disagrees")
		}

		return pres
	}

	return pres
}

func detectArtifactType(ctx context.Context, manifest *registry2.Manifest) (string, bool) {
	acceptableArtifactTypes := []registry2.ArtifactType{
		registry2.ArtifactTypeCosignSignature,
		registry2.ArtifactTypeCosignSBOM,
		registry2.ArtifactTypeSigstoreBundle,
	}

	if manifest.Config.Digest != "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		slog.WarnContext(ctx, "metadata config should point to well known {} digest, but got instead %s (config ignored).", manifest.Config)
	}

	// Modern OCI-1.1: config should be empty type, artifact type should exist.
	if manifest.Config.MediaType == registry2.MediaTypeOCIEmptyJSON {
		slog.DebugContext(ctx, "modern config media type detected")

		if !slices.Contains(acceptableArtifactTypes, manifest.ArtifactType) {
			slog.WarnContext(ctx, "metadata with no artifact type", manifest.ArtifactType)

			return string(manifest.ArtifactType), false
		}

		slog.DebugContext(ctx, "returning artifact type")

		return string(manifest.ArtifactType), true
	}

	// Transitional model: artifact type is slapped as a media type for config. Really, cosign? :/
	if slices.Contains(acceptableArtifactTypes, registry2.ArtifactType(manifest.Config.MediaType)) {
		slog.DebugContext(ctx, "acceptable transitional config media type detected.")

		if manifest.ArtifactType != "" {
			// In that case, we do NOT expect an ArtifactType...
			slog.WarnContext(ctx, "signature with both config media type and artifact type. This is bizarre.", manifest.ArtifactType)

			if slices.Contains(acceptableArtifactTypes, manifest.ArtifactType) {
				slog.DebugContext(ctx, "returning artifact type")

				return string(manifest.ArtifactType), true
			}

			slog.WarnContext(ctx, "ignoring unrecognized artifact type", manifest.ArtifactType)
		}

		slog.DebugContext(ctx, "returning config media type")

		return string(manifest.Config.MediaType), true
	}

	// Bonkers media-type
	slog.WarnContext(ctx, "metadata has a config media type we did not understand. This is bizarre.", manifest.Config.MediaType)
	// Do we have an artifact type that makes sense?
	if slices.Contains(acceptableArtifactTypes, manifest.ArtifactType) {
		slog.DebugContext(ctx, "returning artifact type")

		return string(manifest.ArtifactType), true
	}

	slog.WarnContext(ctx, "metadata has no usable type information", manifest)

	return string(manifest.Config.MediaType), false
}

func buildMetadata(ctx context.Context, ref *types.Image, manifest *registry2.Manifest, addr *addressable) ([]*Signature, error) {
	// Layers verification
	if len(manifest.Layers) == 0 {
		slog.WarnContext(ctx, "metadata manifest has no layers! This is just invalid. Bailing out.", manifest.Layers)
		return nil, ErrInvalidSignature
	}

	// Media/artifact type verification. Non-fatal, but worth surfacing.
	artType, recognized := detectArtifactType(ctx, manifest)
	pres := presumedType(ref.Tag, artType)

	signatures := []types.Signature{}
	sboms := []*SBOM{}

	signer := signature.NewSigner()

	// Now, let's look at the layers.
	for _, layer := range manifest.Layers {
		// Retrieve the blob and parse it
		readCloser, err := downloadBlob(ctx, ref, layer)
		if err != nil {
			slog.ErrorContext(ctx, "Error downloading metadata. IGNORED.", "error", err, "layer", layer)
			continue
		}

		metadata, err := io.ReadAll(readCloser)
		if err != nil {
			slog.ErrorContext(ctx, "Error downloading signature. This signature will be ignored.", "error", err, "layer", layer)
			continue
		}

		sig, err := signer.ReadSignature(metadata, layer.Annotations, types.MediaType(layer.MediaType))
		if err == nil {
			signatures = append(signatures, sig)
		}

		switch layer.MediaType {
		case registry2.LayerMediaTypeCycloneDXJSON,
			registry2.Tier2LayerMediaTypeCycloneDXXML,
			registry2.Tier2LayerMediaTypeSyftJSON,
			registry2.Tier2LayerMediaTypeSPDXJSON,
			registry2.Tier2LayerMediaTypeSPDXText:
			if pres != PresumedSBOM {
				slog.WarnContext(ctx, "we got a SBOM inside a manifest that hinted at something else", artType)
			}

			sboms = append(sboms, &SBOM{
				Annotations: layer.Annotations,
				MediaType:   layer.MediaType,
				Payload:     metadata,
			})
		case registry2.LayerMediaTypeDSSEEnvelope:
			// crane manifest cgr.dev/chainguard/nginx:sha256-b843064853c4b690b6cad32073c9695a4d7672fb5eb6f00bac35d2885935ce84.att | jq '.layers[0]'
		case registry2.LayerMediaTypeInToto:
			// Need predicateType to figure out what it is
		case registry2.Tier3LayerMediaTypeInTotoBundle:
			// Need predicateType to figure out what it is
		}

	}
}
