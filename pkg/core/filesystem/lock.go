//nolint:gochecknoglobals
package filesystem

import "go.farcloser.world/core/filesystem"

var (
	// Unlock releases a flock.
	Unlock = filesystem.Unlock
	// Lock acquires an exclusive lock.
	Lock = filesystem.Lock
	// ReadOnlyLock acquires a shareable read lock.
	ReadOnlyLock = filesystem.ReadOnlyLock
	// TryLock tries to acquire an exclusive lock, return an error if it fails.
	TryLock = filesystem.TryLock
	// WriteFile atomically writes data to a file using write-to-temp + rename.
	WriteFile = filesystem.WriteFile
)
