package utilities //revive:disable-line:var-naming

import (
	"os"
	"path/filepath"
	"runtime"
)

// RuntimeDir returns the user's runtime directory for storing sockets and other
// ephemeral runtime files.
//
// On Linux, this returns $XDG_RUNTIME_DIR (typically /run/user/<uid>).
// On macOS, this returns ~/.quark/run.
// On other platforms, this falls back to os.TempDir().
//
// The returned path is not guaranteed to exist; callers should create it as needed.
func RuntimeDir() string {
	switch runtime.GOOS {
	case "linux":
		if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
			return dir
		}

		return os.TempDir()
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".quark", "run")
		}

		return os.TempDir()
	default:
		return os.TempDir()
	}
}
