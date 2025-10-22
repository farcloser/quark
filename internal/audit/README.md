# Package audit

## Purpose

Provides Dockerfile and container image quality auditing using industry-standard tools (hadolint and dockle).

## Functionality

- **Dockerfile linting** via hadolint - detects best practice violations, security issues, and potential bugs in Dockerfiles
- **Image security auditing** via dockle - checks built images for security misconfigurations, secrets, and compliance violations
- **Custom quality checks** - extensible framework for project-specific quality requirements (TODO: not yet implemented)

## Public API

```go
type Auditor struct { ... }
func NewAuditor(log zerolog.Logger) *Auditor

// Audit operations
func (a *Auditor) AuditDockerfile(dockerfilePath string) (*Result, error)
func (a *Auditor) AuditImage(imageRef, registryHost, username, password, ruleSet string) (*Result, error)
func (a *Auditor) CheckCustom(dockerfilePath string) (*Result, error)

// Result types
type Result struct {
    DockerfileIssues int
    ImageIssues      int
    Passed           bool
    Output           string
}
```

## Design

- **Tool abstraction**: Wraps external CLI tools (hadolint, dockle) with structured Go interface
- **Automatic tool installation**: Uses internal/tools to ensure required binaries are available
- **Configurable strictness**: Supports different rule sets (strict, recommended, minimal) for dockle audits
- **Structured output**: Parses JSON output from tools and provides formatted, human-readable results

## Dependencies

- External: `hadolint` (Dockerfile linter), `dockle` (image security scanner)
- Internal: `internal/tools` for tool installation management
