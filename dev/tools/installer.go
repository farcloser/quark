package tools

import "context"

// Installer is the common interface for tool installers.
type Installer interface {
	// Ensure ensures the tool is installed and returns the path to the binary.
	Ensure(ctx context.Context) (string, error)
}
