package buildkit

import "errors"

var (
	// ErrMetadataNoDigest indicates the metadata file is missing a digest.
	ErrMetadataNoDigest = errors.New("no digest found in metadata")
	// ErrMetadataFailedReading indicates the metadata file could not be read.
	ErrMetadataFailedReading = errors.New("failed to read metadata file")
	// ErrMetadataFailedParsing indicates the metadata file could not be parsed.
	ErrMetadataFailedParsing = errors.New("failed to parse metadata")

	// ErrDockerCommandFailed indicates a docker command execution failed.
	ErrDockerCommandFailed = errors.New("docker command failed")
	// ErrBuildFailed indicates a multi-platform build operation failed.
	ErrBuildFailed = errors.New("build failed")
	// ErrBuildCancelled indicates the build was cancelled via context.
	ErrBuildCancelled = errors.New("build cancelled")
	// ErrRegistryLoginFailed indicates registry authentication failed.
	ErrRegistryLoginFailed = errors.New("registry login failed")
	// ErrCreateBuilder indicates buildx builder creation failed.
	ErrCreateBuilder = errors.New("failed to create builder")
	// ErrCreateSocket indicates Unix socket creation failed.
	ErrCreateSocket = errors.New("failed to create socket")
	// ErrAcquireSocket indicates socket acquisition failed.
	ErrAcquireSocket = errors.New("failed to acquire socket")
	// ErrRemoveStaleSocket indicates stale socket removal failed.
	ErrRemoveStaleSocket = errors.New("failed to remove stale socket")
	// ErrCreateSocketDir indicates socket directory creation failed.
	ErrCreateSocketDir = errors.New("failed to create socket directory")
	// ErrCreateMetadataFile indicates metadata file creation failed.
	ErrCreateMetadataFile = errors.New("failed to create metadata file")
	// ErrReadBuildMetadata indicates build metadata reading failed.
	ErrReadBuildMetadata = errors.New("failed to read build metadata")
	// ErrGenerateRandomBytes indicates random byte generation failed.
	ErrGenerateRandomBytes = errors.New("failed to generate random bytes")
	// ErrCreateBuilderLockDir indicates builder lock directory creation failed.
	ErrCreateBuilderLockDir = errors.New("failed to create builder lock directory")
	// ErrAcquireBuilderLock indicates builder lock acquisition failed.
	ErrAcquireBuilderLock = errors.New("failed to acquire builder lock")
)
