package attest

import "errors"

// ErrNoStatements is returned when no VEX statements or files are provided.
var ErrNoStatements = errors.New("no VEX statements or files provided")
