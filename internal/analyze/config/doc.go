// Package config provides OCI image config analysis without downloading layers.
//
// This package provides two implementations:
//   - Wrapper: Uses dockle's manifest assessor library directly
//   - Native: Re-implements the checks without external dependencies
//
// Both analyze the OCI image config blob (~5KB) to detect security issues,
// avoiding the need to download full layer blobs (50-500MB).
package config
