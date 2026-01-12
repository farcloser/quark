package image

import (
	"context"
	"io"
	"log/slog"

	"github.com/farcloser/quark/internal/network"
	"github.com/farcloser/quark/internal/registry2"
	"github.com/farcloser/quark/internal/types"
)

func downloadBlob(ctx context.Context, ref *types.Image, descriptor *registry2.Descriptor) (io.ReadCloser, error) {
	downloadURLs(ctx, descriptor)

	return registry2.NewClient().ReadBlob(ctx, ref, descriptor.Digest)
}

func downloadManifest(ctx context.Context, ref *types.Image, descriptor *registry2.Descriptor) (*registry2.Content, error) {
	downloadURLs(ctx, descriptor)

	return registry2.NewClient().ReadManifest(ctx, ref)
}

// download allows retrieving content from alternative urls provided in the descriptor.
// Retrieval uses local content-addressable caching, guaranteeing the digest matches
// and that a subsequent call to ReadBlob or ReadManifest will not round trip to the server
// if we found valid content at one of the URLs.
func downloadURLs(ctx context.Context, descriptor *registry2.Descriptor) {
	for _, u := range descriptor.URLs {
		_, err := network.FetchWithCache(ctx, u, descriptor.Digest)
		if err != nil {
			slog.ErrorContext(ctx, "failed to fetch from URL", "url", u, "error", err)

			continue
		}

		break
	}
}
