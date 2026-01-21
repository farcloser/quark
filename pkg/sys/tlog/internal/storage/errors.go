package storage

import "errors"

var (
	// ErrUnsignedCommit indicates the commit we were asked to inspect is unsigned.
	ErrUnsignedCommit = errors.New("unsigned commit")
	// ErrFailedReadingCommitSignature indicates a broken signature on the commit we were asked to inspect.
	ErrFailedReadingCommitSignature = errors.New("failed to retrieve commit signature")
	// ErrSyncConflict indicates max retries exceeded during sync.
	ErrSyncConflict = errors.New("sync conflict: max retries exceeded")
)
