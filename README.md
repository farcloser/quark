# Quark

Quark is a declarative container image management tool written in Go, designed for building, syncing, scanning, and auditing container images across multiple platforms and registries.

## Features

- **Multi-Platform Image Sync**: Copy images between registries with digest verification (linux/amd64, linux/arm64)
- **Registry Collection**: Store registry credentials in a plan, automatically looked up by domain
- **Distributed Builds**: Build multi-platform images using SSH-accessible buildkit nodes
- **Vulnerability Scanning**: Scan images with Trivy for CVEs and security vulnerabilities
- **Quality Auditing**: Audit images with dockle for best practices
- **Version Checking**: Monitor upstream image registries for new releases with digest verification
- **Type-Safe Plans**: Define operations as Go programs with compile-time validation
- **Infrastructure Agnostic**: No hard-coded dependencies on specific registries or infrastructure
- **Idempotent Operations**: Digest-based change detection prevents unnecessary work
- **1Password Integration**: Retrieve credentials securely from 1Password vaults

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Quark CLI                           │
│          (quark execute -p plan.go)                     │
└────────────────────┬────────────────────────────────────────┘
                     │
         ┌───────────┴──────────┐
         │                      │
    ┌────▼─────┐          ┌─────▼──────┐
    │   SDK    │          │  Internal  │
    │          │          │  Packages  │
    └────┬─────┘          └─────┬──────┘
         │                      │
    ┌────▼──────────────────────▼─────┐
    │  • Registry Client (OCI)        │
    │  • Buildkit Client (SSH)        │
    │  • Trivy Scanner (local)        │
    │  • Audit Tools (hadolint/dockle)│
    └────┬────────────────────────────┘
         │
    ┌────▼──────────────────────┐
    │  Target Systems           │
    │  • Registries (GHCR, etc) │
    │  • Buildkit Nodes (SSH)   │
    └───────────────────────────┘
```

## Installation

```bash
make build
make install  # Installs to $GOPATH/bin
```

## Usage

### Create a Plan File

Plans are Go programs that define your container image operations:

```go
package main

import (
    "context"
    "github.com/rs/zerolog/log"
    "github.com/farcloser/quark/sdk"
)

func main() {
    ctx := context.Background()

    // Configure logging
    sdk.ConfigureDefaultLogger(ctx)

    plan := sdk.NewPlan("my-pipeline")

    // Retrieve credentials from 1Password
    ghcrCreds, err := sdk.GetSecret(ctx,
        "op://Security/ghcr-credentials",
        []string{"username", "password", "domain"})
    if err != nil {
        log.Fatal().Err(err).Msg("Failed to retrieve credentials")
    }

    // Register credentials - stored in plan's registry collection
    plan.Registry(ghcrCreds["domain"]).
        Username(ghcrCreds["username"]).
        Password(ghcrCreds["password"]).
        Build()

    // Create image references with domain, name, and version
    sourceImage := sdk.NewImage("library/alpine").
        Domain("docker.io").
        Version("3.20").
        Digest("sha256:abc...").  // Required for sync security
        Build()

    destImage := sdk.NewImage("my-org/alpine").
        Domain("ghcr.io").
        Version("v3.20").
        Build()

    // Sync image between registries
    // Registry credentials are automatically looked up by image domain
    plan.Sync("alpine-sync").
        Source(sourceImage).
        Destination(destImage).
        Build()

    // Check for new versions
    plan.VersionCheck("alpine-version").
        Source(sourceImage).
        Build()

    // Scan image for vulnerabilities
    plan.Scan("scan-alpine").
        Source(destImage).
        Severity(sdk.SeverityCritical, sdk.ActionFail).
        Severity(sdk.SeverityHigh, sdk.ActionWarn).
        Build()

    // Audit image with dockle
    plan.Audit("audit-alpine").
        Source(destImage).
        RuleSet(sdk.RuleSetStrict).
        IgnoreCheck("CIS-DI-0005").
        IgnoreCheck("CIS-DI-0006").
        Build()

    // Execute plan
    if err := plan.Execute(ctx); err != nil {
        log.Fatal().Err(err).Msg("Plan execution failed")
    }
}
```

### Execute a Plan

```bash
quark execute -p plan.go
quark execute -p plan.go --dry-run  # Simulate without changes
```

## Key Concepts

### Registry Collection Pattern

Registries are stored in the plan by domain and automatically looked up when needed:

1. **Register credentials once** with `plan.Registry(domain)`
2. **Create images** with `sdk.NewImage(name).Domain(domain)`
3. **Operations automatically find credentials** by matching image domain to registered registry

This eliminates passing registry objects everywhere and makes the API cleaner.

### Domain Normalization

- Empty domain `""` normalizes to `"docker.io"` (Docker Hub default)
- Explicit domains like `"ghcr.io"`, `"quay.io"` used as-is
- Registry lookup uses normalized domains for consistency

### Digest-Based Security

- **Sync operations require source digest** - ensures you sync exactly what you verified
- **Never trust registry-reported digests** - compute digests locally from pulled images
- **Digest mismatch detection** - warns if tag has been mutated upstream

## Design Principles

1. **Infrastructure Agnostic**: No hard-coded registries or infrastructure dependencies
2. **Registry Collection**: Credentials stored by domain, automatically looked up
3. **Digest-First Security**: Always verify content by digest, never trust tags alone
4. **Type-Safe Configuration**: Plans are Go programs with compile-time validation
5. **Idempotent Operations**: Digest-based change detection prevents unnecessary work
6. **Builder Pattern**: Fluent, readable API inspired by Hadron
7. **SSH-Based Security**: Buildkit nodes accessed via SSH (no custom TLS)

## SDK Operations

Quark provides these operations in the SDK:

### Registry Collection

Registries are stored in the plan and automatically looked up by domain:

```go
// Register Docker Hub credentials
plan.Registry("docker.io").
    Username("myuser").
    Password("mytoken").
    Build()

// Register GHCR credentials
plan.Registry("ghcr.io").
    Username("myorg").
    Password("ghp_token").
    Build()

// Empty domain normalizes to "docker.io"
plan.Registry("").
    Username("myuser").
    Password("mytoken").
    Build()
```

When you create images with domains, the plan automatically uses the correct credentials.

### Image References

Create typed image references with domain, name, version, and optional digest:

```go
// Source image (for sync - requires digest)
sourceImage := sdk.NewImage("timberio/vector").
    Domain("docker.io").
    Version("0.40.0-distroless-static").
    Digest("sha256:abc123...").
    Build()

// Destination image (digest populated after sync)
destImage := sdk.NewImage("my-org/vector").
    Domain("ghcr.io").
    Version("v0").
    Build()
```

### Sync

Copy images between registries with digest verification:

```go
plan.Sync("sync-vector").
    Source(sourceImage).      // Must have digest
    Destination(destImage).   // Domain used for registry lookup
    Build()
```

- Source image MUST have digest specified (security requirement)
- Registry credentials automatically looked up by image domain
- Returns destination image with populated digest after execution
- Multi-platform images (amd64/arm64) automatically handled

### VersionCheck

Check for new image versions in upstream registries:

```go
plan.VersionCheck("check-alpine").
    Source(sourceImage).  // Checks for newer versions
    Build()
```

- Reports if update is available
- Shows current and latest versions
- Includes latest digest for security

### Scan

Scan images for vulnerabilities using Trivy:

```go
plan.Scan("scan-alpine").
    Source(destImage).
    Severity(sdk.SeverityCritical, sdk.ActionFail).
    Severity(sdk.SeverityHigh, sdk.ActionWarn).
    Severity(sdk.SeverityMedium, sdk.ActionWarn).
    Build()
```

Severity levels:
- `sdk.SeverityCritical`
- `sdk.SeverityHigh`
- `sdk.SeverityMedium`
- `sdk.SeverityLow`

Actions:
- `sdk.ActionFail` - Fail execution if found
- `sdk.ActionWarn` - Warn but continue

### Audit

Audit images with dockle for best practices:

```go
plan.Audit("audit-image").
    Source(destImage).
    RuleSet(sdk.RuleSetStrict).
    IgnoreCheck("CIS-DI-0005").  // Allow USER root
    IgnoreCheck("CIS-DI-0006").  // Allow latest tag
    Build()
```

Rule sets:
- `sdk.RuleSetStrict` - All CIS benchmark checks
- `sdk.RuleSetDefault` - Standard checks

Common ignore checks:
- `CIS-DI-0001` - Allow root user
- `CIS-DI-0005` - Allow non-numeric USER
- `CIS-DI-0006` - Allow latest tag
- `CIS-DI-0008` - Allow setuid/setgid

### Build

Build multi-platform container images using buildkit:

```go
plan.Build("build-app").
    Context("./docker").
    Dockerfile("Dockerfile").  // optional, defaults to Context/Dockerfile
    BuildNode(node).           // SSH buildkit node
    Tag("ghcr.io/org/app:v1.0").
    Platform(sdk.PlatformAMD64).
    Platform(sdk.PlatformARM64).
    Build()
```

Platforms:
- `sdk.PlatformAMD64` - linux/amd64
- `sdk.PlatformARM64` - linux/arm64

## 1Password Integration

Quark includes built-in 1Password integration for secure credential retrieval:

```go
// Retrieve multiple fields from a single 1Password item
credentials, err := sdk.GetSecret(ctx,
    "op://Security (build)/deploy.registry.rw",
    []string{"username", "password", "domain"})
if err != nil {
    log.Fatal().Err(err).Msg("Failed to retrieve credentials")
}

// Use retrieved credentials
plan.Registry(credentials["domain"]).
    Username(credentials["username"]).
    Password(credentials["password"]).
    Build()
```

This is more efficient than calling `op` multiple times, as it retrieves all fields in a single 1Password CLI call.

## Real-World Examples

See the `straw/plans/` directory for production examples:

- **`images-sync/plan.go`** - Sync multiple images from Docker Hub to GHCR with version checking
- **`images-validate/plan.go`** - Audit and scan synced images for security compliance
- **`update/plan.go`** - Automated image update workflow with digest verification
- **`outdated/plan.go`** - Check all images for available updates

## Technology Stack

- **Language**: Go 1.24.0
- **CLI**: urfave/cli/v2
- **Logging**: zerolog
- **Registry**: google/go-containerregistry
- **Build**: moby/buildkit
- **Scanning**: Trivy
- **Linting**: hadolint, dockle
