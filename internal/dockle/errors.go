package dockle

import "errors"

var (
	// ErrParsingFailed indicates dockle output parsing failed.
	ErrParsingFailed = errors.New("failed to parse dockle JSON output")
	// ErrScanFailed indicates dockle hard failed while trying to scan.
	ErrScanFailed = errors.New("failed to scan")
)
