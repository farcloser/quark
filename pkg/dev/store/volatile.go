package store

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/farcloser/quark/pkg/core/digest"
	"github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/fault"
)

const (
	volatileDataFile = "data"
)

// Volatile provides content-addressed ephemeral storage with file-based reference counting.
// Safe for concurrent access across multiple processes.
// Resistant to process crashes - OS automatically releases file locks when process dies.
type Volatile struct {
	rc        *filesystem.Locker
	algorithm digest.Algorithm
}

// NewVolatile creates a new volatile store at the given root directory.
// See types.Algorithm for supported hashing algorithms.
func NewVolatile(root string, algorithm digest.Algorithm) *Volatile {
	return &Volatile{
		rc:        filesystem.NewLocker(root),
		algorithm: algorithm,
	}
}

// Acquire ensures content exists at a path and returns that path with a release function.
// Multiple concurrent readers (even across processes) can acquire the same content.
// The file is guaranteed to exist until release is called.
// Release is soft - if other readers exist, the file is not deleted.
// Crash-resistant: OS releases file locks when process dies, enabling cleanup.
func (v *Volatile) Acquire(content []byte) (string, func(), error) {
	h := v.algorithm.Hash()
	h.Write(content)
	contentHash := hex.EncodeToString(h.Sum(nil))

	//nolint:wrapcheck
	return v.rc.Acquire(contentHash, func(dir string) (string, func(), error) {
		dataPath := filepath.Join(dir, volatileDataFile)

		// Write data if it doesn't exist (atomic write)
		if _, err := os.Stat(dataPath); os.IsNotExist(err) {
			if err := filesystem.WriteFile(dataPath, content, filesystem.FilePermissionsPrivate); err != nil {
				return "", nil, fmt.Errorf("%w: data file: %w", fault.ErrWriteFailure, err)
			}
		}

		// No cleanup needed - Locker handles directory removal
		return dataPath, nil, nil
	})
}
