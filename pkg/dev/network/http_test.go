package network_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/farcloser/quark/pkg/dev/network"
	"github.com/farcloser/quark/pkg/fault"
)

func computeDigest(data []byte) string {
	hash := sha256.Sum256(data)

	return "sha256:" + hex.EncodeToString(hash[:])
}

func TestFetchWithCache_Success(t *testing.T) {
	t.Parallel()

	content := []byte("test content for caching")
	contentDigest := computeDigest(content)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer server.Close()

	result, err := network.FetchWithCache(t.Context(), server.URL, contentDigest)
	if err != nil {
		t.Fatalf("FetchWithCache failed: %v", err)
	}

	if string(result) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", result, content)
	}
}

func TestFetchWithCache_CacheHit(t *testing.T) {
	t.Parallel()

	// Use unique content per test run to ensure we control the cache state
	unique := fmt.Sprintf("cached content %d", time.Now().UnixNano())
	content := []byte(unique)
	contentDigest := computeDigest(content)

	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer server.Close()

	// First fetch - should hit the server (content is unique, not cached)
	result1, err := network.FetchWithCache(t.Context(), server.URL, contentDigest)
	if err != nil {
		t.Fatalf("first FetchWithCache failed: %v", err)
	}

	if string(result1) != string(content) {
		t.Errorf("first fetch content mismatch: got %q, want %q", result1, content)
	}

	// Second fetch with same digest - should use cache
	result2, err := network.FetchWithCache(t.Context(), server.URL, contentDigest)
	if err != nil {
		t.Fatalf("second FetchWithCache failed: %v", err)
	}

	if string(result2) != string(content) {
		t.Errorf("second fetch content mismatch: got %q, want %q", result2, content)
	}

	// Server should only be called once - second call used cache
	if callCount != 1 {
		t.Errorf("expected server to be called once, got %d calls", callCount)
	}
}

func TestFetchWithCache_HTTPError(t *testing.T) {
	t.Parallel()

	content := []byte("this won't be returned")
	contentDigest := computeDigest(content)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := network.FetchWithCache(t.Context(), server.URL, contentDigest)
	if err == nil {
		t.Fatal("expected error for HTTP 404, got nil")
	}

	if !errors.Is(err, fault.ErrUnacceptableResponse) {
		t.Errorf("expected ErrUnacceptableResponse, got: %v", err)
	}
}

func TestFetchWithCache_DigestMismatch(t *testing.T) {
	t.Parallel()

	actualContent := []byte("actual content from server")
	wrongContent := []byte("different content for wrong digest")
	wrongDigest := computeDigest(wrongContent)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(actualContent)
	}))
	defer server.Close()

	_, err := network.FetchWithCache(t.Context(), server.URL, wrongDigest)
	if err == nil {
		t.Fatal("expected error for digest mismatch, got nil")
	}

	if !errors.Is(err, fault.ErrHashMismatch) {
		t.Errorf("expected ErrHashMismatch, got: %v", err)
	}
}

func TestFetchWithCache_ContextCancelled(t *testing.T) {
	t.Parallel()

	content := []byte("content")
	contentDigest := computeDigest(content)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	_, err := network.FetchWithCache(ctx, server.URL, contentDigest)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestFetchWithCache_InvalidURL(t *testing.T) {
	t.Parallel()

	content := []byte("content")
	contentDigest := computeDigest(content)

	_, err := network.FetchWithCache(t.Context(), "http://invalid.invalid.invalid:99999/path", contentDigest)
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}

	if !errors.Is(err, fault.ErrNetworkError) {
		t.Errorf("expected ErrNetworkError, got: %v", err)
	}
}

func TestFetchWithCache_ServerError(t *testing.T) {
	t.Parallel()

	content := []byte("content")
	contentDigest := computeDigest(content)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := network.FetchWithCache(t.Context(), server.URL, contentDigest)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}

	if !errors.Is(err, fault.ErrUnacceptableResponse) {
		t.Errorf("expected ErrUnacceptableResponse, got: %v", err)
	}
}
