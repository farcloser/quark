package registry2

// Cosign signature layer media type.
const (
	ArtifactTypeCosignSignature   ArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"
	ArtifactTypeCosignSBOM        ArtifactType = "application/vnd.dev.cosign.artifact.sbom.v1+json"
	ArtifactTypeCosignAttestation ArtifactType = "application/vnd.dev.cosign.artifact.att.v1+json"
	ArtifactTypeSigstoreBundle    ArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	ArtifactTypeDocker            ArtifactType = "application/vnd.docker.attestation.manifest.v1+json"

	// Trivy         | trivy-sbom/cyclonedx                             | SBOM               |
	// Trivy         | trivy-vuln/results                               | Vulnerability scan |
	// Notation      | application/vnd.cncf.notary.signature            | Signature          |
	// ORAS examples | application/vnd.example.sbom.v1+json             | SBOM               |.
)
