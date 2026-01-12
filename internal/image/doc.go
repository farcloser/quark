// Package image provides high-level helper for images manipulation.
// Specifically, it leverages internal/registry for network operations, and dev/store CacheStore for local caching,
// and exposes a graph of objects (index -> manifests -> signatures | attestations).
package image
