package docker

import "errors"

var (
	// ErrBuildkitdStart indicates the buildkitd container failed to start.
	ErrBuildkitdStart = errors.New("failed to start buildkitd container")

	// ErrDockerCommandFailed indicates a docker command failed.
	ErrDockerCommandFailed = errors.New("docker command failed")
)
