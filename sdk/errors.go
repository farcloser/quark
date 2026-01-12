package sdk

import (
	"errors"

	"github.com/farcloser/quark/internal/reference"
)

// Registry errors.
var (
	// ErrRegistryAuth indicates registry authentication failure.
	ErrRegistryAuth = errors.New("registry authentication failed")

	// ErrDockerLogin indicates docker login command failed.
	ErrDockerLogin = errors.New("docker login failed")
)

// Image name errors.
var (
	// ErrInvalidImageReference indicates that the user is walking on their head.
	ErrInvalidImageReference = reference.ErrInvalidImageReference

	// ErrImageNameRequired indicates image name is required.
	ErrImageNameRequired = errors.New("image name is required")
)

// Node errors.
var (
	// ErrNodeEndpointRequired indicates node endpoint is required.
	ErrNodeEndpointRequired = errors.New("node endpoint is required")

	// ErrNodeConnectionFailed indicates SSH connection to node failed.
	ErrNodeConnectionFailed = errors.New("failed to connect to node")
)

// Plan errors.
var (
	// ErrPlanExecutionFailed indicates plan execution failed.
	ErrPlanExecutionFailed = errors.New("plan execution failed")
)
