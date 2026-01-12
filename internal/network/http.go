// Package network provides HTTP utilities for content fetching.
package network

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/dev/store"
	"github.com/farcloser/quark/internal/types"
)

// FetchWithCache fetches content from a URL and caches it by digest.
// If the content is already cached, returns immediately.
// The cache verifies the digest on write - returns error if content doesn't match.
func FetchWithCache(ctx context.Context, url string, digest types.Digest) ([]byte, error) {
	cacheKey := digest.Encoded()
	cache := store.GetStoreCache()

	reader, writer, err := cache.Acquire(cacheKey)
	if err != nil {
		return nil, fmt.Errorf("%w: cache acquire: %w", fault.ErrFilesystemFailure, err)
	}

	if writer == nil {
		// Cache hit - read from cache
		defer reader.Close()

		content, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("%w: cache read: %w", fault.ErrReadFailure, err)
		}

		return content, nil
	}

	// Cache miss - fetch from URL
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

	// Read content from the pipe reader
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: read cached: %w", fault.ErrReadFailure, err)
	}

	return content, nil
}
