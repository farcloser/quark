package dockerfile

import "errors"

// ErrLintFailed indicates the linting operation failed.
var ErrLintFailed = errors.New("dockerfile linting failed")
