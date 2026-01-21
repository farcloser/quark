package store

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/farcloser/quark/pkg/core/digest"
	"github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/fault"
)

const (
	cacheSubdir    = "store"
	volatileSubdir = "volatile"
)

//nolint:gochecknoglobals // Global stores with lazy initialization
var (
	cacheStore    *Cache
	volatileStore *Volatile
	cacheOnce     sync.Once
	volatileOnce  sync.Once
)

// GetStoreCache returns the global cache store instance, initializing it on first access.
// Registers a shutdown handler to run garbage collection on exit.
func GetStoreCache() *Cache {
	cacheOnce.Do(func() {
		cacheDir, err := filesystem.CacheDir()
		if err != nil {
			panic(fmt.Errorf("%w: %w", fault.ErrSystemFailure, err))
		}

		cacheStore = NewCache(filepath.Join(cacheDir, cacheSubdir))
	})

	return cacheStore
}

// GetStoreVolatile returns the global volatile store instance, initializing it on first access.
func GetStoreVolatile() *Volatile {
	volatileOnce.Do(func() {
		runtimeDir, err := filesystem.RuntimeDir()
		if err != nil {
			panic(fmt.Errorf("%w: %w", fault.ErrSystemFailure, err))
		}

		volatileStore = NewVolatile(filepath.Join(runtimeDir, volatileSubdir), digest.BLAKE2b256)
	})

	return volatileStore
}
