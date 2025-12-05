package sdk

import (
	"errors"

	"github.com/farcloser/quark/internal/reference"
)

// Registry errors.
var (
	// ErrRegistryAuth indicates registry authentication failure.
	ErrRegistryAuth = errors.New("registry authentication failed")
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
