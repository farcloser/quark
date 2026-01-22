package registry2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/farcloser/quark/pkg/core/network"
	"github.com/farcloser/quark/pkg/dev/store"
	"github.com/farcloser/quark/pkg/fault"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	gcrtypes "github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/farcloser/quark/internal/types"
)

type client struct{}

func (*client) Ping(ctx context.Context, img *types.Image) error {
	reg, err := parseRegistry(img)
	if err != nil {
		return err
	}

	auth := getAuthenticator(img.Registry)

	baseTransport := http.DefaultTransport
	if t := buildTransport(img.Registry); t != nil {
		baseTransport = t
	}

	// Create transport with auth negotiation - this validates credentials.
	_, err = transport.NewWithContext(
		ctx,
		reg,
		auth,
		baseTransport,
		[]string{reg.Scope(transport.PullScope)},
	)
	if err != nil {
		return wrapTransportError(err)
	}

	return nil
}

func (*client) ResolveDigest(
	ctx context.Context,
	img *types.Image,
) (types.Digest, error) {
	ref, err := parseReference(img)
	if err != nil {
		return "", err
	}

	desc, err := remote.Head(ref, remoteOptions(ctx, img.Registry)...)
	if err != nil {
		return "", wrapTransportError(err)
	}

	return types.Digest(desc.Digest.String()), nil
}

func (c *client) ReadManifest(ctx context.Context, img *types.Image) (*Content, error) {
	if img.Digest == "" {
		return nil, fmt.Errorf("%w: image must have digest", fault.ErrInvalidArgument)
	}

	cacheKey := img.Digest.Encoded()
	cache := store.GetStoreCache()

	reader, writer, err := cache.Acquire(cacheKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRegistryOperationFailed, err)
	}

	if writer == nil {
		// Cache hit - read from cache.
		// Note: "hit" includes two cases:
		//   1. Complete data exists (true cache hit)
		//   2. Another goroutine is writing (we get an inProgressReader that tails their write)
		//
		// Case 2 can fail with ErrWriteFailure if the other writer fails (e.g., registry
		// returns 404). When this happens, we retry: the failed writer has released its
		// lock, so we'll become the writer and fetch from the registry ourselves, getting
		// the actual error (e.g., ErrNotFound) instead of a generic ErrWriteFailure.
		defer reader.Close()

		raw, err := io.ReadAll(reader)
		if err != nil {
			if errors.Is(err, fault.ErrWriteFailure) {
				slog.WarnContext(ctx, "cache writer failed, retrying as writer")

				return c.ReadManifest(ctx, img)
			}

			return nil, fmt.Errorf("%w: %w", ErrRegistryOperationFailed, err)
		}

		return NewContent(raw, img.Digest), nil
	}

	// Cache miss - fetch from registry, write to cache, read from pipe
	defer reader.Close()

	ref, err := parseReference(img)
	if err != nil {
		_ = writer.Close()

		return nil, err
	}

	desc, err := remote.Get(ref, remoteOptions(ctx, img.Registry)...)
	if err != nil {
		_ = writer.Close()

		return nil, wrapTransportError(err)
	}

	rawManifest, err := desc.RawManifest()
	if err != nil {
		_ = writer.Close()

		return nil, fmt.Errorf("%w: %w", ErrRegistryError, err)
	}

	// Write to cache (tees to reader via pipe)
	_, _ = writer.Write(rawManifest)
	// Close writer to signal EOF to reader
	_ = writer.Close()

	// Read from pipe
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRegistryOperationFailed, err)
	}

	return NewContent(raw, img.Digest), nil
}

func (*client) ListTags(ctx context.Context, img *types.Image) ([]string, error) {
	ref, err := parseRepository(img)
	if err != nil {
		return nil, err
	}

	tags, err := remote.List(ref, remoteOptions(ctx, img.Registry)...)
	if err != nil {
		return nil, wrapTransportError(err)
	}

	return tags, nil
}

func (*client) ListReferrers(ctx context.Context, img *types.Image) (*Content, error) {
	if img.Digest == "" {
		return nil, fmt.Errorf("%w: image must have digest", fault.ErrInvalidArgument)
	}

	repo, err := parseRepository(img)
	if err != nil {
		return nil, err
	}

	ref := repo.Digest(img.Digest.String())

	index, err := remote.Referrers(ref, remoteOptions(ctx, img.Registry)...)
	if err != nil {
		return nil, wrapTransportError(err)
	}

	raw, err := index.RawManifest()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRegistryError, err)
	}

	return NewContent(raw, ""), nil
}

func (c *client) ReadBlob(
	ctx context.Context,
	img *types.Image,
	digest types.Digest,
) (io.ReadCloser, error) {
	cacheKey := digest.Encoded()
	cache := store.GetStoreCache()

	reader, writer, err := cache.Acquire(cacheKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRegistryOperationFailed, err)
	}

	if writer == nil {
		// Cache hit - return reader directly.
		// Note: same inProgressReader issue as ReadManifest (see comment there).
		// For blobs we return the reader for streaming, so we can't retry here.
		// If the underlying writer fails, caller gets ErrWriteFailure when reading.
		// TODO: wrap reader to retry on ErrWriteFailure if needed.
		return reader, nil
	}

	// Cache miss - fetch from registry
	repo, err := parseRepository(img)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()

		return nil, err
	}

	layer, err := remote.Layer(
		repo.Digest(digest.String()),
		remoteOptions(ctx, img.Registry)...,
	)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()

		return nil, wrapTransportError(err)
	}

	networkReader, err := layer.Compressed()
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()

		return nil, wrapTransportError(err)
	}

	// Stream from network to cache writer in background
	// Writer tees to both cache file and the returned reader
	go func() {
		_, _ = io.Copy(writer, networkReader)
		_ = networkReader.Close()
		_ = writer.Close()
	}()

	return reader, nil
}

func (*client) WriteManifest(
	ctx context.Context,
	img *types.Image,
	content *Content,
) (types.Digest, error) {
	var ref name.Reference

	// If no tag or digest provided, push by content's digest
	if img.Tag == "" && img.Digest == "" {
		repo, err := parseRepository(img)
		if err != nil {
			return "", err
		}

		ref = repo.Digest(content.Digest().String())
	} else {
		var err error

		ref, err = parseReference(img)
		if err != nil {
			return "", err
		}
	}

	if err := remote.Put(ref, content, remoteOptions(ctx, img.Registry)...); err != nil {
		return "", wrapTransportError(err)
	}

	return content.Digest(), nil
}

func (*client) WriteBlob(
	ctx context.Context,
	img *types.Image,
	digest types.Digest,
	size int64,
	content io.Reader,
) error {
	repo, err := parseRepository(img)
	if err != nil {
		return err
	}

	// Convert to v1.Hash.
	hash, err := v1.NewHash(digest.String())
	if err != nil {
		return fmt.Errorf("%w: %w", fault.ErrInvalidArgument, err)
	}

	// XXX clarify this
	// Create a streaming layer with known digest and size.
	layer, err := partial.CompressedToLayer(&blobLayer{
		digest:    hash,
		size:      size,
		content:   content,
		mediaType: gcrtypes.OCIUncompressedLayer,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRegistryError, err)
	}

	err = remote.WriteLayer(repo, layer, remoteOptions(ctx, img.Registry)...)
	if err != nil {
		return wrapTransportError(err)
	}

	return nil
}

// blobLayer implements partial.CompressedLayer for streaming blob uploads.
type blobLayer struct {
	digest    v1.Hash
	size      int64
	content   io.Reader
	mediaType gcrtypes.MediaType
}

func (b *blobLayer) Digest() (v1.Hash, error) {
	return b.digest, nil
}

func (b *blobLayer) Compressed() (io.ReadCloser, error) {
	if rc, ok := b.content.(io.ReadCloser); ok {
		return rc, nil
	}

	return io.NopCloser(b.content), nil
}

func (b *blobLayer) Size() (int64, error) {
	return b.size, nil
}

func (b *blobLayer) MediaType() (gcrtypes.MediaType, error) {
	return b.mediaType, nil
}

func (*client) DeleteManifest(ctx context.Context, img *types.Image) error {
	ref, err := parseReference(img)
	if err != nil {
		return err
	}

	if err := remote.Delete(ref, remoteOptions(ctx, img.Registry)...); err != nil {
		return wrapTransportError(err)
	}

	return nil
}

// parseRegistry extracts registry from Image.
func parseRegistry(img *types.Image) (name.Registry, error) {
	if img.Registry == nil {
		return name.Registry{}, fmt.Errorf("%w: missing registry", fault.ErrInvalidArgument)
	}

	reg, err := name.NewRegistry(img.Registry.Domain)
	if err != nil {
		return name.Registry{}, fmt.Errorf("%w: %w", fault.ErrInvalidArgument, err)
	}

	return reg, nil
}

// parseRepository constructs a repository reference from Image.
func parseRepository(img *types.Image) (name.Repository, error) {
	if img.Registry == nil {
		return name.Repository{}, fmt.Errorf("%w: missing registry", fault.ErrInvalidArgument)
	}

	repoStr := fmt.Sprintf("%s/%s", img.Registry.Domain, img.Path)

	repo, err := name.NewRepository(repoStr)
	if err != nil {
		return name.Repository{}, fmt.Errorf("%w: %w", fault.ErrInvalidArgument, err)
	}

	return repo, nil
}

// parseReference constructs a full reference (repo + tag or digest) from Image.
func parseReference(img *types.Image) (name.Reference, error) {
	repo, err := parseRepository(img)
	if err != nil {
		return nil, err
	}

	// Prefer digest if available.
	if img.Digest != "" {
		return repo.Digest(string(img.Digest)), nil
	}

	// Fall back to tag.
	if img.Tag != "" {
		return repo.Tag(img.Tag), nil
	}

	return nil, fmt.Errorf("%w: image must have tag or digest", fault.ErrInvalidArgument)
}

// getAuthenticator returns the appropriate authenticator for the registry.
func getAuthenticator(creds *types.RegistryCredentials) authn.Authenticator {
	if creds == nil {
		return authn.Anonymous
	}

	// Token auth takes precedence.
	if creds.Token != "" {
		return &authn.Bearer{Token: creds.Token}
	}

	// Basic auth.
	if creds.Username != "" && creds.Password != "" {
		return &authn.Basic{
			Username: creds.Username,
			Password: creds.Password,
		}
	}

	return authn.Anonymous
}

// remoteOptions returns remote options for registry operations.
func remoteOptions(ctx context.Context, creds *types.RegistryCredentials) []remote.Option {
	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuth(getAuthenticator(creds)),
		remote.WithRetryStatusCodes(network.RetryStatusCodes...),
		remote.WithRetryBackoff(remote.Backoff{
			Duration: 1 * time.Second,
			Factor:   2.0,
			Jitter:   0.1,
			Steps:    5,
		}),
	}

	if t := buildTransport(creds); t != nil {
		opts = append(opts, remote.WithTransport(t))
	}

	return opts
}

// buildTransport creates a custom transport if TLS customization is needed.
// Returns nil if no custom transport is needed (use default).
// Supports independent configuration of:
//   - Custom CA: trust a private registry's certificate
//   - Client cert (mTLS): authenticate with client certificate
func buildTransport(creds *types.RegistryCredentials) http.RoundTripper {
	if creds == nil {
		return nil
	}

	hasClientCert := creds.Cert != "" && creds.Key != ""
	hasCustomCA := creds.CA != ""

	if !hasClientCert && !hasCustomCA {
		return nil
	}

	httpTransport := network.NewTransport()

	// Trust custom CA for private registries.
	if hasCustomCA {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM([]byte(creds.CA)) {
			httpTransport.TLSClientConfig.RootCAs = pool
		}
	}

	// Client certificate for mTLS authentication.
	if hasClientCert {
		cert, err := tls.X509KeyPair([]byte(creds.Cert), []byte(creds.Key))
		if err == nil {
			httpTransport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		}
	}

	return httpTransport
}

// wrapTransportError converts go-containerregistry errors to our error types.
func wrapTransportError(err error) error {
	if err == nil {
		return nil
	}

	// Check for context errors first.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	// Check for transport errors with HTTP status codes.
	var transportErr *transport.Error
	if errors.As(err, &transportErr) {
		switch transportErr.StatusCode {
		case http.StatusNotFound:
			return fmt.Errorf("%w: %w", fault.ErrNotFound, err)
		case http.StatusUnauthorized:
			return fmt.Errorf("%w: %w", fault.ErrAuthenticationFailure, err)
		case http.StatusForbidden:
			return fmt.Errorf("%w: %w", ErrForbidden, err)
		}
	}

	return fmt.Errorf("%w: %w", ErrRegistryError, err)
}
