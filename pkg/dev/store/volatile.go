package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	filesystem2 "github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/fault"
)

const (
	volatileDataFile = "data"
)

// Volatile provides content-addressed ephemeral storage with file-based reference counting.
// Safe for concurrent access across multiple processes.
// Resistant to process crashes - OS automatically releases file locks when process dies.
type Volatile struct {
	rc *filesystem2.Locker
}

// NewVolatile creates a new volatile store at the given root directory.
func NewVolatile(root string) *Volatile {
	return &Volatile{rc: filesystem2.NewLocker(root)}
}

// Acquire ensures content exists at a path and returns that path with a release function.
// Multiple concurrent readers (even across processes) can acquire the same content.
// The file is guaranteed to exist until release is called.
// Release is soft - if other readers exist, the file is not deleted.
// Crash-resistant: OS releases file locks when process dies, enabling cleanup.
func (v *Volatile) Acquire(content []byte) (string, func(), error) {
	hash := sha256.Sum256(content)
	digest := hex.EncodeToString(hash[:])

	return v.rc.Acquire(digest, func(dir string) (string, func(), error) {
		dataPath := filepath.Join(dir, volatileDataFile)

		// Write data if it doesn't exist (atomic write)
		if _, err := os.Stat(dataPath); os.IsNotExist(err) {
			if err := filesystem2.WriteFile(dataPath, content, filesystem2.FilePermissionsPrivate); err != nil {
				return "", nil, fmt.Errorf("%w: data file: %w", fault.ErrWriteFailure, err)
			}
		}

		// No cleanup needed - Locker handles directory removal
		return dataPath, nil, nil
	})
}
