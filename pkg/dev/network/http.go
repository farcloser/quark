package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/farcloser/quark/pkg/dev/store"
	"github.com/farcloser/quark/pkg/fault"
)

// FetchWithCache fetches content from a URL and caches it by digest.
// If the content is already cached, returns immediately.
// The cache verifies the digest on write - returns error if content doesn't match.
//
// IMPORTANT: Caller must call core/network.SetDefaults() at startup to configure
// http.DefaultTransport with proper timeouts and TLS settings.
func FetchWithCache(ctx context.Context, url, dgst string) ([]byte, error) {
	cache := store.GetStoreCache()

	for {
		reader, writer, err := cache.Acquire(dgst)
		if err != nil {
			return nil, fmt.Errorf("%w: cache acquire: %w", fault.ErrFilesystemFailure, err)
		}

		if writer == nil {
			// Cache hit or concurrent write in progress - read from cache
			content, err := io.ReadAll(reader)
			_ = reader.Close()

			if err != nil {
				// If a concurrent writer failed, retry to become the writer ourselves
				if errors.Is(err, fault.ErrWriteFailure) {
					continue
				}

				return nil, fmt.Errorf("%w: cache read: %w", fault.ErrReadFailure, err)
			}

			return content, nil
		}

		// Cache miss - fetch from URL
		return fetchAndCache(ctx, url, reader, writer)
	}
}

func fetchAndCache(ctx context.Context, url string, reader io.ReadCloser, writer io.WriteCloser) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()

		return nil, fmt.Errorf("%w: create request: %w", fault.ErrInvalidArgument, err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()

		return nil, fmt.Errorf("%w: fetch: %w", fault.ErrNetworkError, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = reader.Close()
		_ = writer.Close()

		return nil, fmt.Errorf("%w: HTTP %d", fault.ErrUnacceptableResponse, resp.StatusCode)
	}

	// Stream response to cache writer (cache verifies digest on close)
	_, err = io.Copy(writer, resp.Body)
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()

		return nil, fmt.Errorf("%w: read body: %w", fault.ErrNetworkError, err)
	}

	// Close writer - this verifies the digest
	if err := writer.Close(); err != nil {
		_ = reader.Close()

		return nil, fmt.Errorf("%w: digest verification: %w", fault.ErrHashMismatch, err)
	}

	// Read content from the reader
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: read cached: %w", fault.ErrReadFailure, err)
	}

	return content, nil
}
