# Package audit

## Purpose

Provides Dockerfile and container image quality auditing using industry-standard tools (godolint SDK and dockle).

## Functionality

- **Dockerfile linting** via godolint SDK - detects best practice violations, security issues, and potential bugs in Dockerfiles
- **Image security auditing** via dockle - checks built images for security misconfigurations, secrets, and compliance violations
- **Configurable severity levels** - supports different rule sets (strict, recommended, minimal)
- **Check exclusions** - ability to ignore specific dockle checks via IgnoreChecks

## Public API

```go
type Auditor struct { ... }
func NewAuditor(log zerolog.Logger) *Auditor

// Audit operations (all accept context.Context for cancellation)
func (a *Auditor) AuditDockerfile(ctx context.Context, dockerfilePath string) (*Result, error)
func (a *Auditor) AuditImage(ctx context.Context, imageRef string, opts ImageAuditOptions) (*Result, error)

// Configuration types
type ImageAuditOptions struct {
    RegistryHost string   // Registry host for authentication (optional)
    Username     string   // Registry username (optional)
    Password     string   // Registry password (optional)
    RuleSet      string   // Rule set: "strict", "recommended", or "minimal"
    IgnoreChecks []string // Dockle checks to ignore (e.g., "DKL-DI-0005")
}

// Result types
type Result struct {
    DockerfileIssues int
    ImageIssues      int
    Passed           bool
    Output           string
}
```

## Design

- **SDK integration**: Uses godolint SDK directly for Dockerfile linting (no external binary dependency)
- **Tool abstraction**: Wraps dockle CLI with structured Go interface
- **Automatic tool installation**: Uses internal/tools to ensure dockle is available
- **Configurable strictness**: Supports different rule sets for dockle audits:
  - `strict`: Fails on FATAL and WARN levels
  - `recommended`: Fails only on FATAL level
  - `minimal`: Fails only on FATAL level
- **Structured output**: Provides formatted, human-readable results from linting and scanning
- **Credential security**: Registry credentials passed via environment variables (not process list)

## Dependencies

- External: `dockle` (image security scanner)
- Internal: `github.com/farcloser/godolint/sdk` for Dockerfile linting, `internal/tools` for dockle installation management

## Security Considerations

- **Credential handling**: Registry passwords passed via DOCKLE_PASSWORD environment variable
- **Environment inheritance**: All audits inherit parent environment variables (os.Environ())
- **Scoped authentication**: DOCKLE_AUTH_URL restricts credentials to specific registry
