//nolint:gochecknoglobals
package filesystem

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"go.farcloser.world/core/filesystem"

	"github.com/farcloser/quark/pkg/fault"
)

// ValidatePathComponent enforces OS-specific filename restrictions on a single path component.
var ValidatePathComponent = filesystem.ValidatePathComponent

// ValidatePath validates a full path by checking each component.
// Returns an error if any component is invalid.
func ValidatePath(path string) error {
	// Iterate over path components
	for component := range strings.SplitSeq(path, string(os.PathSeparator)) {
		// Skip empty components (from leading/trailing/double separators)
		if component == "" {
			continue
		}

		if err := ValidatePathComponent(component); err != nil {
			return fmt.Errorf("%w: invalid path component %q: %w", fault.ErrInvalidArgument, component, err)
		}
	}

	return nil
}

// ValidateSocketPath checks that a Unix socket path does not exceed OS-specific limits.
// Unix sockets have a hard limit on path length due to the fixed-size sun_path field
// in struct sockaddr_un:
//   - Linux: 108 bytes (including null terminator)
//   - macOS/BSD: 104 bytes (including null terminator)
//
// Returns an error if the path is too long for the current platform.
func ValidateSocketPath(path string) error {
	// Need room for null terminator, so max usable length is maxSocketPathLen - 1
	maxLen := maxSocketPathLen - 1

	if len(path) > maxLen {
		return fmt.Errorf("%w: socket path exceeds %s limit of %d bytes (got %d): %s",
			fault.ErrInvalidArgument, runtime.GOOS, maxLen, len(path), path)
	}

	return nil
}
