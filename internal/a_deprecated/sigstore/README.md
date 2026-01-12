# Package sigstore

## Purpose

Provides OCI container image signing and verification using sigstore-go, supporting both keyless (Fulcio/OIDC) and key-based signing.

## Functionality

- **Keyless signing** - Sign images using OIDC identity (Fulcio certificates)
- **Key-based signing** - Sign images using ECDSA private keys
- **Signature verification** - Verify keyless signatures against Sigstore public good infrastructure
- **Key verification** - Verify signatures against provided public keys
- **Transparency log** - Upload signatures to Rekor for auditability
- **Signature inspection** - Check if images are signed without requiring trust policy
- **Custom annotations** - Attach metadata to signatures

## Public API

```go
// Signing
func Sign(ctx context.Context, opts *SignOptions) error

type SignOptions struct {
    ImageRef                 name.Reference
    Digest                   string            // sha256:...
    OIDCIssuer               string            // For keyless signing
    OIDCToken                string            // JWT token
    PrivateKey               []byte            // PEM-encoded key
    KeyPassword              string            // Optional
    RegistryAuth             *RegistryAuth
    PublishToTransparencyLog bool
    Annotations              map[string]string
    Log                      *slog.Logger
}

// Keyless verification (Fulcio/OIDC)
func Verify(ctx context.Context, opts *VerifyOptions) (*VerificationResult, error)

type VerifyOptions struct {
    ImageRef     name.Reference
    Digest       string
    RegistryAuth *RegistryAuth
    Log          *slog.Logger
}

// Key-based verification
func VerifyWithPublicKey(ctx context.Context, opts *VerifyWithKeyOptions) (*VerificationResult, error)

type VerifyWithKeyOptions struct {
    ImageRef     name.Reference
    Digest       string
    PublicKey    []byte  // PEM-encoded
    RegistryAuth *RegistryAuth
    Log          *slog.Logger
}

// Signature inspection (no trust policy required)
func Inspect(ctx context.Context, opts *InspectOptions) (*InspectResult, error)

// Result types
type VerificationResult struct {
    Digest      string
    Keyless     *KeylessSignerInfo  // nil for key-based
    IsKeyBased  bool
    Annotations map[string]string
}

type KeylessSignerInfo struct {
    Subject string  // Email or URI from certificate
    Issuer  string  // OIDC issuer URL
}

type InspectResult struct {
    IsSigned    bool
    Digest      string
    Keyless     *KeylessSignerInfo
    IsKeyBased  bool
    Annotations map[string]string
}

type RegistryAuth struct {
    Username string
    Password string
}
```

## Signing Methods

### Keyless (Fulcio/OIDC)

1. Create ephemeral keypair
2. Get certificate from Fulcio using OIDC token
3. Sign payload with ephemeral key
4. Optionally upload to Rekor transparency log
5. Push signature to registry as OCI artifact

### Key-based

1. Parse PEM-encoded private key (PKCS8 or EC)
2. Sign payload with private key
3. Optionally upload to Rekor with public key
4. Push signature to registry

## Verification

### Keyless Verification
- Fetches signature from registry
- Builds sigstore bundle from OCI artifact
- Verifies against Sigstore public good trusted root (via TUF)
- Validates certificate chain, SCTs, and Rekor inclusion

### Key Verification
- Fetches signature from registry
- Verifies signature against provided public key
- No transparency log verification required

## Signature Format

Compatible with cosign simple signing format:
- Tag: `sha256-<digest>.sig`
- Layer media type: `application/vnd.dev.cosign.simplesigning.v1+json`
- Annotations: `dev.sigstore.cosign/signature`, `dev.sigstore.cosign/certificate`, `dev.sigstore.cosign/bundle`

## Dependencies

- External: `sigstore/sigstore-go`, `sigstore/rekor`, `google/go-containerregistry`
- Internal: None

## Security Considerations

- **Private keys in memory**: Private keys parsed and used in memory only
- **Certificate validation**: Full certificate chain validation via Sigstore TUF
- **Transparency log**: Signatures uploaded to Rekor are publicly auditable
- **Digest binding**: Signatures bound to specific image digests
- **Credential isolation**: Registry credentials scoped to specific operations
