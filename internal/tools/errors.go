package tools

import "errors"

var (
	// ErrUnableToInstall indicates a tool installation failed.
	ErrUnableToInstall = errors.New("install failed")
	// ErrToolNotInstalled indicates that despite calling installation successfully, the tool is still not there.
	// Indicative that something is really-really wrong.
	ErrToolNotInstalled = errors.New("tool not installed")
)
