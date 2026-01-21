package kit

import (
	"github.com/farcloser/quark/pkg/fault"
)

// XXX fix this.
var (
	// ErrTrustInvalidArgument indicates no valid certificates were found in the provided PEM data.
	ErrTrustInvalidArgument = fault.ErrInvalidArgument

	// ErrEnvVarNotSet indicates required environment variable is not set.
	ErrEnvVarNotSet = fault.ErrInvalidArgument

	// ErrEnvFileLoad indicates failed to load a .env file.
	ErrEnvFileLoad = fault.ErrReadFailure

	// ErrSecretsReadFailed indicates a secret retrieval operation failed.
	ErrSecretsReadFailed = fault.ErrReadFailure
)
