package cache

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/core/trust"
	"github.com/farcloser/quark/pkg/fault"
)

const (
	cacheSubdir = "tlog"
	cacheFile   = "cache.json"
)

// cachePath returns a unique cache directory for a repository path.
func cachePath(repoPath string) (string, error) {
	return filesystem.CacheDir(cacheSubdir, trust.HashString(repoPath))
}

// Load loads a cached trustState for the given repository path.
// Returns nil if no cache exists or cache is unreadable.
func Load(repoPath string) ([]byte, error) {
	cacheDir, err := cachePath(repoPath)
	if err != nil {
		return nil, fmt.Errorf("get cache dir: %w", err)
	}

	// Acquire read lock on the directory
	lock, err := filesystem.ReadOnlyLock(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("acquire read lock: %w", err)
	}

	defer func() { _ = filesystem.Unlock(lock) }()

	data, err := os.ReadFile(filepath.Join(cacheDir, cacheFile)) //nolint:gosec // path is derived from controlled input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("read cache: %w", err)
	}

	return data, nil
}

// Save persists a trustState to the cache for the given repository path.
func Save(repoPath string, state []byte) error {
	cacheDir, err := cachePath(repoPath)
	if err != nil {
		return fmt.Errorf("get cache dir: %w", err)
	}

	// Acquire exclusive lock on the directory
	lock, err := filesystem.Lock(cacheDir)
	if err != nil {
		return fmt.Errorf("acquire write lock: %w", err)
	}

	defer func() { _ = filesystem.Unlock(lock) }()

	if err := filesystem.WriteFile(filepath.Join(cacheDir, cacheFile), state, filesystem.FilePermissionsPrivate); err != nil {
		return fmt.Errorf("%w: write cache: %w", fault.ErrFilesystemFailure, err)
	}

	return nil
}
