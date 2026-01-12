package image

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/internal/network"
	"github.com/farcloser/quark/internal/registry2"
	"github.com/farcloser/quark/internal/types"
)

//artifactTypeSigstoreBundle   = ArtifactType(LayerMediaTypeSigstoreBundle)

var (
	ErrInvalidSignature = errors.New("invalid signature")
)

func buildImage(ctx context.Context, registryResource *registry2.Manifest, addr *addressable) (*Manifest, error) {
}

func buildAttestation(ctx context.Context, registryResource *registry2.Manifest, addr *addressable) (*Attestation, error) {
}

func buildSBOM(ctx context.Context, registryResource *registry2.Manifest, addr *addressable) (*SBOM, error) {
}

func buildIndex(ctx context.Context, registryResource *registry2.Index, addr *addressable) (*Index, error) {
	//content, err := registry2.NewClient().ReadManifest(ctx, img)
	//if err != nil {
	//	return nil, err
	//}
	//
	//addr, err := newAddressable(ctx, content, img, source)
	//if err != nil {
	//	return nil, err
	//}

	//if registryResource, err := addr.content.ParseIndex(); err == nil {
	//}

	index := &Index{
		addressable: *addr,
		parsed:      registryResource,
	}

	// Iterate the linked resources
	for _, subAddr := range addr.linked {
		// The sub resource is an index
		if subRegistryResource, err := subAddr.content.ParseIndex(); err == nil {
			// Is it the referers index? If yes, retrieve all the resources and put them in the seal
			if subAddr.source == SourceFallbackIndex || subAddr.source == SourceReferrersAPI {
				idxSeal, err := buildIndex(ctx, subRegistryResource, subAddr)
				if err != nil {
					return nil, err
				}
				if subAddr.source == SourceReferrersAPI {
					index.referersIndex = idxSeal
				} else {
					index.legacyIndex = idxSeal
				}

				for _, res := range idxSeal.spuriousSignatures {
					if res.subject.Digest != index.Digest {
						slog.Warn("seal references signatures that do not match")
					} else {
						index.Signatures = append(index.Signatures, res)
					}
				}

				for _, res := range idxSeal.spuriousAttestations {
					if res.subject.Digest != index.Digest {
						slog.Warn("seal references attestations that do not math")
					} else {
						index.Attestations = append(index.Attestations, res)
					}
				}

				for _, res := range idxSeal.spuriousSBOM {
					if res.subject.Digest != index.Digest {
						slog.Warn("seal references SBOM that do not math")
					} else {
						index.SBOM = append(index.SBOM, res)
					}
				}
			} else {
				// Otherwise, a regular index... We just don't know what to do with these...
				idx, err := buildIndex(ctx, subRegistryResource, subAddr)
				if err != nil {
					return nil, err
				}
				index.Indexes = append(index.Indexes, idx)
				slog.Warn("found an index inside an index, keeping for reference, but we ignore them")
			}

			continue
		}

		// The subResource is a manifest. What is it?
		if subRegistryResource, err := subAddr.content.ParseManifest(); err == nil {
			// Just a regular image
			if subAddr.descriptor.Platform != types.Unknown && subAddr.descriptor.Platform != nil {
				if img, err := buildImage(ctx, subRegistryResource, subAddr); err == nil {
					index.Manifests = append(index.Manifests, img)
				} else {
					slog.Warn("failed to analyze linked image")
				}
				continue
			}

			// Not a regular image manifest.
			// This is an attestation / signature / provenance.
			switch subAddr.descriptor.MediaType {
			case registry2.LayerMediaTypeCosignSignature:
				if sig, err := buildSignature(ctx, subRegistryResource, subAddr); err == nil {
					if sig.subject.Digest != index.Digest {
						index.spuriousSignatures = append(index.spuriousSignatures, sig)
					} else {
						index.Signatures = append(index.Signatures, sig)
					}
				} else {
					slog.Warn("failed to analyze linked signature")
				}
				continue
			case registry2.LayerMediaTypeDSSEEnvelope:
				if sig, err := buildAttestation(ctx, subRegistryResource, subAddr); err == nil {
					if sig.subject.Digest != index.Digest {
						index.spuriousAttestations = append(index.spuriousAttestations, sig)
					} else {
						index.Attestations = append(index.Attestations, sig)
					}
				} else {
					slog.Warn("failed to analyze linked attestation")
				}
				continue
			case registry2.LayerMediaTypeCycloneDXJSON:
				if sig, err := buildSBOM(ctx, subRegistryResource, subAddr); err == nil {
					if sig.subject.Digest != index.Digest {
						index.spuriousSBOM = append(index.spuriousSBOM, sig)
					} else {
						index.SBOM = append(index.SBOM, sig)
					}
				} else {
					slog.Warn("failed to analyze linked SBOM")
				}
				continue
			}
		}

		return index, nil
	}
}

func newAddressable(ctx context.Context, content *registry2.Content, img *types.Image, source ArtifactSource) (*addressable, error) {
	addr := &addressable{
		content:           content,
		Digest:            content.Digest(),
		InlineAnnotations: map[string]string{},
		source:            source,
	}

	if registryObject, err := content.ParseIndex(); err == nil {
		addr.MediaType = registryObject.MediaType
		addr.subject = registryObject.Subject
		/*
			This REQUIRED property specifies the image manifest schema version. For this version of the specification,
			this MUST be 2 to ensure backward compatibility with older versions of Docker.
			The value of this field will not change.
			This field MAY be removed in a future version of the specification.
		*/
		// We are more tolerant though, we just assume it is 2 and move on.
		// The thing HAS parsed as an index, and we are interpreting it as-is.
		// Which means that extensions if any are just ignored.
		if registryObject.SchemaVersion != 2 && registryObject.SchemaVersion != 0 {
			slog.Warn("invalid schema version, assuming version 2 %d", registryObject.SchemaVersion)
		}

		// Same. We warn, but carry on.
		if registryObject.MediaType != registry2.MediaTypeOCIIndex && registryObject.MediaType != registry2.MediaTypeDockerIndex {
			slog.Warn("unrecognized inline media-type for index - interpreting as OCI index", registryObject.MediaType)
		}

		// We don't know anything about artifact-types at this point...
		if registryObject.ArtifactType != "" {
			slog.Warn("unrecognized artifact-type - ignoring", registryObject.ArtifactType)
		}

		// Now, enumerate manifests and get them.
		for _, manifestDescriptor := range registryObject.Manifests {
			// mediaType: could be a manifest, or an index.
			if manifestDescriptor.MediaType != registry2.MediaTypeOCIIndex &&
				manifestDescriptor.MediaType != registry2.MediaTypeDockerIndex &&
				manifestDescriptor.MediaType != registry2.MediaTypeOCIManifest &&
				manifestDescriptor.MediaType != registry2.MediaTypeDockerManifest {
				slog.Warn("unrecognized manifest descriptor media-type in index - will try our best parsing this...", manifestDescriptor)
			}
			// Platform if unknown/unknown is docker embedding strategy for SBOM and Provenance
			// Otherwise, it is a straight manifest.
			// Retrieve it here, and call either manifest or SBOM / stuff
			// If we have urls, iterate until download succeeds (pre-populate cache)
			downloadURLs(ctx, manifestDescriptor)

			targetImg := &types.Image{
				Registry: img.Registry,
				Path:     img.Path,
				Digest:   manifestDescriptor.Digest,
			}

			subContent, err := registry2.NewClient().ReadManifest(ctx, targetImg)
			if err != nil {
				return nil, err
			}

			// Inherit the parent trust level
			linkedAddressable, err := newAddressable(ctx, subContent, targetImg, source)

			// handle error
			if err != nil {
				return nil, err
			}

			// Attach descriptor
			linkedAddressable.descriptor = manifestDescriptor

			// Attach it to our linked resources
			addr.linked = append(addr.linked, linkedAddressable)
		}

		return addr, nil
	}

	if registryObject, err := content.ParseManifest(); err == nil {
		addr.MediaType = registryObject.MediaType
		addr.subject = registryObject.Subject

		if registryObject.SchemaVersion != 2 && registryObject.SchemaVersion != 0 {
			slog.Warn("invalid schema version, assuming version 2 %d", registryObject.SchemaVersion)
		}

		// We don't know anything about artifact-types at this point...
		if registryObject.ArtifactType != "" {
			slog.Warn("unrecognized artifact-type - ignoring", registryObject.ArtifactType)
		}

		gatherReferers(ctx, img)

		return addr, nil
	}

	return nil, fmt.Errorf("%w: this does not seem to be a manifest nor an index", fault.ErrInvalidArgument)
}

func gatherReferers(ctx context.Context, img *types.Image) ([]*addressable, error) {
	cli := registry2.NewClient()

	linked := []*addressable{}
	// Find a detached signature with legacy tag
	subReference := registry2.SignatureImage(img)
	resolvedDigest, err := cli.ResolveDigest(ctx, subReference)
	if err != nil {
		slog.Warn("no separate signature", "error", err)
	} else {
		subReference.Digest = resolvedDigest
		subContent, err := registry2.NewClient().ReadManifest(ctx, subReference)
		if err != nil {
			slog.Warn("no separate signature", "error", err)
		} else {
			sig, err := newAddressable(ctx, subContent, subReference, SourceLegacyTag)
			if err != nil {
				slog.Debug("no separate signature", "error", err)
			} else {
				linked = append(linked, sig)
			}
		}
	}

	subReference = registry2.AttestationImage(img)
	resolvedDigest, err = cli.ResolveDigest(ctx, subReference)
	if err != nil {
		slog.Warn("no separate attestation", "error", err)
	} else {
		subReference.Digest = resolvedDigest
		subContent, err := registry2.NewClient().ReadManifest(ctx, subReference)
		if err != nil {
			slog.Warn("no separate signature", "error", err)
		} else {
			sig, err := newAddressable(ctx, subContent, subReference, SourceLegacyTag)
			if err != nil {
				slog.Debug("no separate attestation", "error", err)
			} else {
				linked = append(linked, sig)
			}
		}
	}

	subReference = registry2.SBOMImage(img)
	resolvedDigest, err = cli.ResolveDigest(ctx, subReference)
	if err != nil {
		slog.Warn("no separate sbom", "error", err)
	} else {
		subReference.Digest = resolvedDigest
		subContent, err := registry2.NewClient().ReadManifest(ctx, subReference)
		if err != nil {
			slog.Warn("no separate signature", "error", err)

		} else {
			sig, err := newAddressable(ctx, subContent, subReference, SourceLegacyTag)
			if err != nil {
				slog.Debug("no separate attestation", "error", err)
			} else {
				linked = append(linked, sig)
			}
		}
	}

	subReference = registry2.FallbackIndex(img)
	resolvedDigest, err = cli.ResolveDigest(ctx, subReference)
	if err != nil {
		slog.Warn("no separate index", "error", err)
	} else {
		subReference.Digest = resolvedDigest
		subContent, err := registry2.NewClient().ReadManifest(ctx, subReference)
		if err != nil {
			slog.Warn("no separate signature", "error", err)
		} else {
			sig, err := newAddressable(ctx, subContent, subReference, SourceFallbackIndex)
			if err != nil {
				slog.Debug("no separate index", "error", err)
			} else {
				linked = append(linked, sig)
			}
		}
	}

	// Now, the goddamn referrers API
	conContent, err := cli.ListReferrers(ctx, img)
	if err != nil {
		slog.Warn("no separate referrers", "error", err)
	} else {
		// Note, there is no specific reference for the referrers index, it is just the original image.
		sig, err := newAddressable(ctx, conContent, img, SourceReferrersAPI)
		if err != nil {
			slog.Debug("no separate index", "error", err)
		} else {
			linked = append(linked, sig)
		}
	}

	// Return all discovered resources
	return linked, nil
}

/*
	// Retrieve content dependent on its media-type
	if registryObject.Config.MediaType == registry2.MediaTypeOCIEmptyJSON {
		if registryObject.Config.Digest != "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
			slog.Warn("empty media type but unrecognized empty hash - suspicious - ignoring", registryObject.Config)
		}
	}else {
		if registryObject.Config.MediaType != registry2.MediaTypeDockerConfig &&
		registryObject.Config.MediaType != registry2.MediaTypeOCIConfig  {
			slog.Warn("blablabla")
		}
		// Fine. Retrieve the blob.
		blobContent, err := registry2.NewClient().ReadBlob(ctx, img, registryObject.Config.Digest)
		if err != nil {
			return nil, err
		}

		bc, err := io.ReadAll(blobContent)
		if err != nil {
			return nil, err
		}

		parsedConfig := &registry2.ConfigFile{}
		if err := json.Unmarshal(bc, parsedConfig); err != nil {
			return nil, err
		}
	}

*/
