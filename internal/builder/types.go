package builder

// SecretFile represents a secret file on disk with its associated lock.
// The caller must call Release() when done using the secret.
type SecretFile struct {
	ID      string // The secret ID for buildctl
	Path    string // Path to the secret file
	release func()
}

// Release releases the read lock and attempts to clean up the secret file.
// Cleanup only succeeds if no other process is using the secret.
func (sf *SecretFile) Release() {
	if sf.release != nil {
		sf.release()
		sf.release = nil
	}
}
