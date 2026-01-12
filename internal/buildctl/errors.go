package buildctl

import "errors"

var (
	// ErrBuildFailed indicates the build failed.
	ErrBuildFailed = errors.New("build failed")

	// ErrMetadataNoDigest indicates the metadata file did not contain a digest.
	ErrMetadataNoDigest = errors.New("metadata file did not contain image digest")

	// ErrEnsureBuilder indicates ensuring the builder failed.
	ErrEnsureBuilder = errors.New("failed to ensure builder")

	// ErrBuildkitdNotReady indicates buildkitd did not become ready in time.
	ErrBuildkitdNotReady = errors.New("buildkitd not ready")

	// ErrNoOutput indicates neither Tags nor DestPath was specified.
	ErrNoOutput = errors.New("build requires either Tags or DestPath")
)
