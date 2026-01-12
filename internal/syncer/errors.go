package syncer

import "errors"

var (
	// ErrNotFound indicates the source image could not be found.
	ErrNotFound = errors.New("failed to get source image")
	// ErrCreateManifestList indicates failure to create a multi-platform manifest list.
	ErrCreateManifestList = errors.New("failed to create manifest list")
	// ErrCopyImage indicates failure to copy an image to the destination registry.
	ErrCopyImage = errors.New("failed to copy image")
)
