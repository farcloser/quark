# Quark

Quark is a declarative container image management tool written in Go, designed for building, syncing, scanning, and auditing container images across multiple platforms and registries.

## Features

- **Multi-Platform Image Sync**: Copy images between registries with digest verification (linux/amd64, linux/arm64)
- **Registry Authentication**: Define registry credentials in a plan, automatically looked up by domain
- **Distributed Builds**: Build multi-platform images using SSH-accessible BuildKit nodes
- **Vulnerability Scanning**: Scan images with Trivy for CVEs and security vulnerabilities
- **Quality Auditing**: Audit Dockerfiles (godolint) and images (dockle) for best practices
- **Version Checking**: Monitor upstream image registries for new releases with digest verification
- **Type-Safe Plans**: Define operations as Go programs with compile-time validation
- **Infrastructure Agnostic**: No hard-coded dependencies on specific registries or infrastructure
- **Idempotent Operations**: Digest-based change detection prevents unnecessary work
- **1Password Integration**: Retrieve credentials securely from 1Password vaults
- **Auto-Installing Tools**: Trivy and Dockle automatically installed on first use
- **SSH Connection Pooling**: Efficient, secure SSH connections to BuildKit nodes with agent-based authentication

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Quark CLI                               │
│          (quark execute -p plan.go)                         │
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
    │  • BuildKit Client (SSH)        │
    │  • Trivy Scanner (local)        │
    │  • Audit Tools (godolint/dockle)│
    └────┬────────────────────────────┘
         │
    ┌────▼──────────────────────┐
    │  Target Systems           │
    │  • Registries (GHCR, etc) │
    │  • BuildKit Nodes (SSH)   │
    └───────────────────────────┘
```

## Installation

```bash
make build
make install  # Installs to $GOPATH/bin
```

Or install directly with Go:

```bash
go install github.com/farcloser/quark/cmd/quark@latest
```

## Prerequisites

Before using Quark, ensure you have the following:

### Required for All Operations

- **Go 1.24+** - For building and running plans

### Required for Specific Operations

- **Docker or BuildKit** - Required for Build operations
- **SSH Agent with Ed25519 Key** - Required for remote builds
- **Registry Credentials** - Required for private registry access
- **1Password CLI** (optional) - For credential management

### SSH Setup (Required for Remote Builds)

Quark uses SSH agent authentication for secure, keyless remote builds. Only Ed25519 keys are supported.

**Generate an Ed25519 key:**
```bash
ssh-keygen -t ed25519 -C "quark-build"
```

**Add key to SSH agent:**
```bash
# Start ssh-agent if not running
eval "$(ssh-agent -s)"

# Add your key
ssh-add ~/.ssh/id_ed25519
```

**Configure SSH config (optional):**
```
# ~/.ssh/config
Host build-node
    HostName build.example.com
    User builder
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_ed25519
```

#### Security Note: First Connection

On first connection to a new build node, if `~/.ssh/known_hosts` doesn't exist or contain the host key,
you'll receive an error with instructions to run:

```bash
ssh-keyscan -H build-node.example.com >> ~/.ssh/known_hosts
```

**IMPORTANT:** This is vulnerable to MITM (man-in-the-middle) attacks on first use. For production systems, obtain host keys through a secure channel.

### Getting Image Digests (Required for Sync/Scan)

Get digests from registries:

**Using docker:**
```bash
docker pull alpine:3.20
docker inspect alpine:3.20 --format='{{index .RepoDigests 0}}'
# Output: alpine@sha256:abc123...
```

**From registry API:**
```bash
curl -sL https://registry.hub.docker.com/v2/library/alpine/manifests/3.20 \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  | jq -r '.config.digest'
```

### 1Password Setup (Optional)

For secure credential management in CI/CD:

**Install 1Password CLI:**
```bash
# macOS
brew install 1password-cli

# Linux
curl -sS https://downloads.1password.com/linux/keys/1password.asc | \
  sudo gpg --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg
```

**Authenticate (local development):**
```bash
op signin
```

**Service account (CI/CD):**
```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
```

## Quick Start

### 1. Create a Plan File

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
    sdk.ConfigureDefaultLogger(ctx)

    plan := sdk.NewPlan("my-pipeline")

    // Create image reference
    image, err := sdk.NewImage("library/alpine").
        Domain("docker.io").
        Version("3.20").
        Build()
    if err != nil {
        log.Fatal().Err(err).Msg("Failed to create image")
    }

    // Check for new versions
    if _, err := plan.VersionCheck("check-alpine").
        Source(image).
        Build(); err != nil {
        log.Fatal().Err(err).Msg("Failed to create version check")
    }

    // Execute plan
    if err := plan.Execute(ctx); err != nil {
        log.Fatal().Err(err).Msg("Plan execution failed")
    }
}
```

### 2. Execute the Plan

```bash
quark execute -p plan.go
quark execute -p plan.go --dry-run  # Simulate without changes
quark execute -p ./plans/           # Execute directory containing main.go
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
- **Platform filtering** - Only linux/amd64 and linux/arm64 images are synced

## Design Principles

1. **Infrastructure Agnostic**: No hard-coded registries or infrastructure dependencies
2. **Registry Collection**: Credentials stored by domain, automatically looked up
3. **Digest-First Security**: Always verify content by digest, never trust tags alone
4. **Type-Safe Configuration**: Plans are Go programs with compile-time validation
5. **Idempotent Operations**: Digest-based change detection prevents unnecessary work
6. **Builder Pattern**: Fluent, readable API inspired by Hadron
7. **SSH-Based Security**: BuildKit nodes accessed via SSH agent (no keys in code)
8. **Defense in Depth**: Destination digests computed locally, not from registry

## SDK Operations

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
sourceImage, err := sdk.NewImage("timberio/vector").
    Domain("docker.io").
    Version("0.40.0-distroless-static").
    Digest("sha256:abc123...").
    Build()
if err != nil {
    log.Fatal().Err(err).Msg("Failed to create source image")
}

// Destination image (digest populated after sync)
destImage, err := sdk.NewImage("my-org/vector").
    Domain("ghcr.io").
    Version("v0").
    Build()
if err != nil {
    log.Fatal().Err(err).Msg("Failed to create destination image")
}
```

**Image Properties:**
- `Name`: Repository name (e.g., "library/alpine", "my-org/app")
- `Domain`: Registry domain (defaults to "docker.io" if empty)
- `Version`: Tag or semantic version (e.g., "3.20", "v1.0.0-alpine")
- `Digest`: SHA256 digest for immutable references (required for security operations)

### Sync

Copy images between registries with digest verification:

```go
if _, err := plan.Sync("sync-vector").
    Source(sourceImage).      // Must have digest
    Destination(destImage).   // Domain used for registry lookup
    Build(); err != nil {
    log.Fatal().Err(err).Msg("Failed to create sync operation")
}
```

**Features:**
- Source image MUST have digest specified (security requirement)
- Registry credentials automatically looked up by image domain
- Returns destination image with locally-computed digest after execution
- Multi-platform images (amd64/arm64) automatically handled
- Creates manifest lists for multi-platform images
- Only linux/amd64 and linux/arm64 platforms are synced

### VersionCheck

Check for new image versions in upstream registries:

```go
if _, err := plan.VersionCheck("check-alpine").
    Source(sourceImage).  // Checks for newer versions
    Build(); err != nil {
    log.Fatal().Err(err).Msg("Failed to create version check")
}
```

**Features:**
- Reports if update is available
- Shows current and latest versions
- Includes latest digest for security
- Warns if current version has no digest (shows actual digest)
- Supports semantic versioning and variant matching (e.g., "alpine", "distroless")

### Scan

Scan images for vulnerabilities using Trivy:

```go
if _, err := plan.Scan("scan-alpine").
    Source(destImage).
    Severity(sdk.SeverityCritical, sdk.ActionError).
    Severity(sdk.SeverityHigh, sdk.ActionWarn).
    Severity(sdk.SeverityMedium, sdk.ActionInfo).
    Format(sdk.FormatTable).  // or FormatJSON, FormatSARIF
    Build(); err != nil {
    log.Fatal().Err(err).Msg("Failed to create scan operation")
}
```

**Severity Levels:**
- `sdk.SeverityCritical`
- `sdk.SeverityHigh`
- `sdk.SeverityMedium`
- `sdk.SeverityLow`
- `sdk.SeverityUnknown`

**Actions:**
- `sdk.ActionError` - Fail execution if found (default)
- `sdk.ActionWarn` - Warn but continue
- `sdk.ActionInfo` - Log informational message

**Output Formats:**
- `sdk.FormatTable` - Human-readable table (default)
- `sdk.FormatJSON` - JSON output
- `sdk.FormatSARIF` - SARIF format for CI/CD integration

**Features:**
- Image MUST have digest specified (security requirement)
- Multi-platform scanning (both amd64 and arm64 scanned automatically)
- Trivy auto-installed on first use

### Audit

Audit Dockerfiles and images for best practices:

```go
// Audit both Dockerfile and image
if _, err := plan.Audit("audit-complete").
    Dockerfile("./Dockerfile").       // godolint SDK
    Source(destImage).                // dockle
    RuleSet(sdk.RuleSetStrict).
    IgnoreChecks("CIS-DI-0005", "CIS-DI-0006").
    Build(); err != nil {
    log.Fatal().Err(err).Msg("Failed to create audit operation")
}

// Audit Dockerfile only
if _, err := plan.Audit("audit-dockerfile").
    Dockerfile("./Dockerfile").
    Build(); err != nil {
    log.Fatal().Err(err).Msg("Failed to create dockerfile audit")
}

// Audit image only
if _, err := plan.Audit("audit-image").
    Source(destImage).
    RuleSet(sdk.RuleSetRecommended).
    Build(); err != nil {
    log.Fatal().Err(err).Msg("Failed to create image audit")
}
```

**Rule Sets:**
- `sdk.RuleSetStrict` - All CIS benchmark checks
- `sdk.RuleSetRecommended` - Standard checks (default)
- `sdk.RuleSetMinimal` - Basic checks only

**Common Ignore Checks:**
- `CIS-DI-0001` - Allow root user
- `CIS-DI-0005` - Allow non-numeric USER
- `CIS-DI-0006` - Allow latest tag
- `CIS-DI-0008` - Allow setuid/setgid binaries
- `DKL-DI-0005` - Allow specific exposed ports

**Features:**
- Dockerfile linting with godolint SDK
- Image security auditing with dockle
- Dockle auto-installed on first use
- Can audit Dockerfile, image, or both in one operation

### Build

Build multi-platform container images using remote BuildKit nodes:

```go
// Define BuildKit nodes (one per platform)
nodeAMD64, err := plan.BuildNode("build-amd64").
    Endpoint("build-amd64.example.com").
    Platform(sdk.PlatformAMD64).
    Build()
if err != nil {
    log.Fatal().Err(err).Msg("Failed to create amd64 build node")
}

nodeARM64, err := plan.BuildNode("build-arm64").
    Endpoint("build-arm64.example.com").
    Platform(sdk.PlatformARM64).
    Build()
if err != nil {
    log.Fatal().Err(err).Msg("Failed to create arm64 build node")
}

// Or use SSH config alias as the endpoint
nodeLocal, err := plan.BuildNode("local-builder").
    Endpoint("local-builder").  // SSH config alias from ~/.ssh/config
    Platform(sdk.PlatformAMD64).
    Build()
if err != nil {
    log.Fatal().Err(err).Msg("Failed to create local build node")
}

// Build multi-platform image
if _, err := plan.Build("build-app").
    Context("./docker").
    Dockerfile("Dockerfile").           // optional, defaults to Context/Dockerfile
    Node(nodeAMD64).
    Node(nodeARM64).
    Tag("ghcr.io/org/app:v1.0").
    Build(); err != nil {
    log.Fatal().Err(err).Msg("Failed to create build operation")
}
```

**Platforms:**
- `sdk.PlatformAMD64` - linux/amd64
- `sdk.PlatformARM64` - linux/arm64

**Features:**
- Connects to BuildKit nodes via SSH
- Uploads build context via SFTP
- Executes remote builds with docker buildx
- Creates multi-platform manifest lists
- Uses SSH agent for authentication (no keys in code)
- Supports SSH config aliases and user@host notation

## 1Password Integration

Quark includes built-in 1Password integration for secure credential retrieval:

```go
// Retrieve multiple fields from a single 1Password item
credentials, err := sdk.GetSecret(ctx,
    "op://Security/ghcr-credentials",
    []string{"username", "password", "domain"})
if err != nil {
    log.Fatal().Err(err).Msg("Failed to retrieve credentials")
}

// Use retrieved credentials
plan.Registry(credentials["domain"]).
    Username(credentials["username"]).
    Password(credentials["password"]).
    Build()

// Retrieve document (like SSH key or kubeconfig)
sshKey, err := sdk.GetSecretDocument(ctx, "op://Security/deploy-key")
if err != nil {
    log.Fatal().Err(err).Msg("Failed to retrieve document")
}
```

**Features:**
- Retrieves all fields in a single 1Password CLI call (efficient)
- Supports both field retrieval (`GetSecret`) and document retrieval (`GetSecretDocument`)
- Works with 1Password CLI and service accounts (for CI/CD)

**Environment Variables:**
- `OP_SERVICE_ACCOUNT_TOKEN` - For CI/CD service account authentication

## SSH Connection Pooling

Quark includes a sophisticated SSH package for secure, efficient connections to BuildKit nodes:

**Features:**
- **Connection Pooling**: Single SSH connection per endpoint, reused across operations
- **Config Support**: Full `~/.ssh/config` parsing (Host, User, Port, Hostname, IdentityFile, IdentitiesOnly)
- **Flexible Endpoints**: IP addresses, hostnames, SSH config aliases, or `user@host` notation
- **Agent Authentication**: Ed25519 keys via SSH agent (no key files in code)
- **Host Key Verification**: Strict `known_hosts` checking with Ed25519-only enforcement
- **SFTP Operations**: Upload files and data to remote build nodes
- **Command Execution**: Run remote commands and capture output

```go
// SSH connections are managed internally by BuildNodes
// No direct SSH code needed in plans
```

## Security Considerations

### Credential Storage in Memory

Quark stores registry credentials (username/password) in plaintext in process memory during plan execution. This is an industry-standard practice used by most container tooling (Docker SDK, Kubernetes client-go, etc.).

**Security Measures:**
- Credentials are **never logged** to stdout, stderr, or log files
- Credentials are **never written to disk** (no swap, no cache files)
- Credentials are **cleared on process exit** (memory released by OS)
- Registry credentials are **scoped** - only sent to the specific registry domain

**Risk:** Process memory dumps could expose credentials if:
- System is compromised while Quark is running
- Core dumps are enabled and triggered during execution
- Debugging tools attach to the Quark process

**Mitigation for Security-Conscious Environments:**

1. **Use 1Password Integration** (recommended for CI/CD):
   ```go
   credentials, _ := sdk.GetSecret(ctx,
       "op://Security/registry",
       []string{"username", "password"})
   ```
   Credentials retrieved just-in-time, minimizing exposure window.

2. **Disable Core Dumps** in production environments:
   ```bash
   ulimit -c 0  # Disable core dumps for current shell
   ```

3. **Run in Isolated Environments**:
   - Container with minimal privileges
   - Dedicated CI runner that's destroyed after use
   - Ephemeral VMs for build operations

4. **Use Short-Lived Tokens** where supported:
   - GitHub: Personal Access Tokens with expiration
   - Docker Hub: Access tokens (not account passwords)
   - Cloud registries: Service account tokens with rotation

**Industry Context:** All major container tools (docker, crane, skopeo, buildx) store credentials in memory during operations. This is an acceptable trade-off for usability vs. security in most environments. For environments requiring additional security, use the mitigations above.

## Environment Variables

Quark supports these environment variables:

- `LOG_LEVEL` - Control logging verbosity (debug, info, warn, error)
- `QUARK_DRY_RUN` - Set to "true" for dry-run mode (set by `--dry-run` flag)
- `OP_SERVICE_ACCOUNT_TOKEN` - 1Password service account token for CI/CD
- `SSH_AUTH_SOCK` - SSH agent socket (required for BuildKit authentication)

**Example:**

```bash
export LOG_LEVEL=debug
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
quark execute -p plan.go
```

## Examples

The `examples/` directory contains working examples:

- **`sync/main.go`** - Multi-platform image sync between registries
- **`scan/main.go`** - Vulnerability scanning with Trivy
- **`audit/main.go`** - Dockerfile and image auditing
- **`build/main.go`** - Multi-platform builds with BuildKit
- **`version-check/main.go`** - Check for image updates

Run an example:

```bash
cd examples/sync
quark execute -p main.go
```

## IMPORTANT caveats

### Concurrency

There is no thread safety guarantees.
Plan building (adding operations, registries, nodes) is not thread-safe.
You should build your plan in a single goroutine, then execute it.
Plan execution is safe and operations run sequentially.

### NOT to be used with untrusted input

This tool is meant to be used by developers and automated system from trusted inputs
(eg: plans that have been authored by the team).

Using it as a service, taking in user controlled input, WILL result in remote code
execution on build-nodes, with the privileges of user associated with the ssh key being used.

## Development

### Build & Install

```bash
make build        # Build binary to ./bin/quark
make install      # Install to $GOPATH/bin
make clean        # Clean build artifacts
```

### Code Quality

```bash
make lint         # Run all linters (Go, YAML, shell, commits, headers, licenses)
make fix          # Auto-fix some linting issues
make test         # Run unit tests with race detection and benchmarks
```

**Linters Used:**
- golangci-lint (v2.0.2) with comprehensive checks
- yamllint - YAML validation
- shellcheck - Shell script linting
- git-validation - Commit message validation
- ltag - License header enforcement
- go-licenses - License compliance checking

### Project Structure

```
quark/
├── cmd/quark/          # CLI entry point
├── sdk/                # Public SDK API
├── internal/           # Internal packages
│   ├── audit/          # godolint SDK/dockle integration
│   ├── buildkit/       # SSH-based BuildKit client
│   ├── registry/       # OCI registry operations
│   ├── sync/           # Image sync implementation
│   ├── tools/          # Tool auto-installation
│   ├── trivy/          # Trivy scanner integration
│   └── version/        # Version checking logic
├── ssh/                # SSH connection pooling
├── examples/           # Working examples
└── Makefile            # Build & development tasks
```

## Technology Stack

- **Language**: go 1.24.3
- **CLI**: urfave/cli/v3 (v3.5.0)
- **Logging**: zerolog (v1.34.0)
- **Registry**: google/go-containerregistry (v0.20.6)
- **Build**: moby/buildkit (v0.25.1)
- **SSH**: golang.org/x/crypto (v0.43.0), pkg/sftp (v1.13.9)
- **Scanning**: Trivy (v0.59.1) - auto-installed
- **Auditing**: godolint SDK (pure Go), Dockle (v0.4.15) - auto-installed

## License

See the [LICENSE](LICENSE) file for details.

## Contributing

1. Follow the existing code style and conventions
2. Run `make lint` before committing
3. Ensure `make test` passes
4. Use conventional commit messages
5. Add tests for new functionality

For detailed linting requirements, see `.golangci.yml`.
