package config

import "time"

// Checkpoint codes for CIS Docker Image benchmarks.
const (
	CodeAvoidRootDefault       = "CIS-DI-0001"
	CodeUseContentTrust        = "CIS-DI-0005"
	CodeAddHealthcheck         = "CIS-DI-0006"
	CodeUseAptGetUpdateNoCache = "CIS-DI-0007"
	CodeUseCOPY                = "CIS-DI-0009"
	CodeAvoidCredential        = "CIS-DI-0010" //nolint:gosec // Not a credential, this is a checkpoint code.
)

// Checkpoint codes for Dockle-specific checks.
const (
	CodeAvoidSudo                       = "DKL-DI-0001"
	CodeAvoidSensitiveDirectoryMounting = "DKL-DI-0002"
	CodeAvoidDistUpgrade                = "DKL-DI-0003"
	CodeUseApkAddNoCache                = "DKL-DI-0004"
	CodeMinimizeAptGet                  = "DKL-DI-0005"
)

// DefaultLevels maps checkpoint codes to their default severity levels.
//
//nolint:gochecknoglobals // Read-only lookup table.
var DefaultLevels = map[string]Level{
	CodeAvoidRootDefault:                LevelWarn,
	CodeUseContentTrust:                 LevelInfo,
	CodeAddHealthcheck:                  LevelInfo,
	CodeUseAptGetUpdateNoCache:          LevelFatal,
	CodeUseCOPY:                         LevelFatal,
	CodeAvoidCredential:                 LevelFatal,
	CodeAvoidSudo:                       LevelFatal,
	CodeAvoidSensitiveDirectoryMounting: LevelFatal,
	CodeAvoidDistUpgrade:                LevelWarn,
	CodeUseApkAddNoCache:                LevelFatal,
	CodeMinimizeAptGet:                  LevelFatal,
}

// Titles maps checkpoint codes to their human-readable descriptions.
//
//nolint:gochecknoglobals // Read-only lookup table.
var Titles = map[string]string{
	CodeAvoidRootDefault:                "Create a user for the container",
	CodeUseContentTrust:                 "Enable content trust for Docker",
	CodeAddHealthcheck:                  "Add HEALTHCHECK instruction to the container image",
	CodeUseAptGetUpdateNoCache:          "Do not use update instructions alone in the Dockerfile",
	CodeUseCOPY:                         "Use COPY instead of ADD in Dockerfile",
	CodeAvoidCredential:                 "Do not store credential in environment variables/files",
	CodeAvoidSudo:                       "Avoid sudo command",
	CodeAvoidSensitiveDirectoryMounting: "Avoid sensitive directory mounting",
	CodeAvoidDistUpgrade:                `Avoid "apt-get dist-upgrade"`,
	CodeUseApkAddNoCache:                `Use "apk add" with --no-cache`,
	CodeMinimizeAptGet:                  "Clear apt-get caches",
}

// ImageConfig represents the OCI image configuration.
// This is the structure of the config blob.
//
//nolint:tagliatelle // OCI image spec uses specific field casing.
type ImageConfig struct {
	Architecture    string    `json:"architecture,omitempty"`
	OS              string    `json:"os,omitempty"`
	Created         time.Time `json:"created"`
	Author          string    `json:"author,omitempty"`
	Config          Config    `json:"config"`
	History         []History `json:"history,omitempty"`
	RootFS          RootFS    `json:"rootfs"`
	ContainerConfig Config    `json:"container_config"`
}

// Config holds container configuration.
//
//nolint:tagliatelle // OCI image spec uses PascalCase for these fields.
type Config struct {
	User        string              `json:"User,omitempty"`
	Env         []string            `json:"Env,omitempty"`
	Cmd         []string            `json:"Cmd,omitempty"`
	Entrypoint  []string            `json:"Entrypoint,omitempty"`
	WorkingDir  string              `json:"WorkingDir,omitempty"`
	Labels      map[string]string   `json:"Labels,omitempty"`
	Volumes     map[string]struct{} `json:"Volumes,omitempty"`
	Healthcheck *HealthConfig       `json:"Healthcheck,omitempty"`
}

// HealthConfig holds HEALTHCHECK configuration.
//
//nolint:tagliatelle // OCI image spec uses PascalCase for these fields.
type HealthConfig struct {
	Test        []string      `json:"Test,omitempty"`
	Interval    time.Duration `json:"Interval,omitempty"`
	Timeout     time.Duration `json:"Timeout,omitempty"`
	StartPeriod time.Duration `json:"StartPeriod,omitempty"`
	Retries     int           `json:"Retries,omitempty"`
}

// History represents a layer history entry.
//
//nolint:tagliatelle // OCI image spec uses snake_case for some fields.
type History struct {
	Created    time.Time `json:"created"`
	Author     string    `json:"author,omitempty"`
	CreatedBy  string    `json:"created_by,omitempty"`
	Comment    string    `json:"comment,omitempty"`
	EmptyLayer bool      `json:"empty_layer,omitempty"`
}

// RootFS describes the root filesystem.
//
//nolint:tagliatelle // OCI image spec uses snake_case for diff_ids.
type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids,omitempty"`
}

// Options configures scanner behavior.
type Options struct {
	// AcceptedEnvKeys are environment variable names to ignore in credential checks.
	AcceptedEnvKeys []string

	// AdditionalSensitiveWords are extra patterns to flag as credentials.
	AdditionalSensitiveWords []string
}
