package sdk

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/ssh"
)

// operation is an internal interface for all executable operations.
// This interface enables unified operation handling and simplifies adding new operation types.
type operation interface {
	execute(ctx context.Context) error
	operationName() string
}

// Plan represents a declarative container image management plan.
type Plan struct {
	name string
	log  zerolog.Logger

	// Resources
	registries    map[string]*Registry // keyed by normalized domain
	buildNodes    []*BuildNode
	syncs         []*Sync
	builds        []*Build
	scans         []*Scan
	audits        []*Audit
	versionChecks []*VersionCheck

	// Operations in execution order (internal)
	operations []operation
}

// normalizeDomain normalizes a registry domain.
// Empty string is normalized to "docker.io" (Docker Hub default).
func normalizeDomain(domain string) string {
	if domain == "" {
		return "docker.io"
	}

	return domain
}

// findSimilarDomain finds a registered domain similar to the target domain.
// Returns empty string if no similar domain found.
// Uses Levenshtein distance to detect typos.
func (plan *Plan) findSimilarDomain(target string) string {
	if len(plan.registries) == 0 {
		return ""
	}

	minDistance := len(target)

	var closest string

	// Find the registered domain with minimum Levenshtein distance
	for registered := range plan.registries {
		distance := levenshteinDistance(target, registered)

		// Only suggest if distance is small (likely a typo, not a completely different domain)
		if distance < minDistance && distance <= 3 {
			minDistance = distance
			closest = registered
		}
	}

	return closest
}

// levenshteinDistance calculates the Levenshtein distance between two strings.
func levenshteinDistance(str1, str2 string) int {
	if len(str1) == 0 {
		return len(str2)
	}

	if len(str2) == 0 {
		return len(str1)
	}

	// Create matrix
	matrix := make([][]int, len(str1)+1)
	for idx := range matrix {
		matrix[idx] = make([]int, len(str2)+1)
		matrix[idx][0] = idx
	}

	for col := range matrix[0] {
		matrix[0][col] = col
	}

	// Fill matrix
	for row := 1; row <= len(str1); row++ {
		for col := 1; col <= len(str2); col++ {
			cost := 0
			if str1[row-1] != str2[col-1] {
				cost = 1
			}

			matrix[row][col] = minInt(
				matrix[row-1][col]+1,      // deletion
				matrix[row][col-1]+1,      // insertion
				matrix[row-1][col-1]+cost, // substitution
			)
		}
	}

	return matrix[len(str1)][len(str2)]
}

// minInt returns the minimum of three integers.
func minInt(first, second, third int) int {
	if first < second {
		if first < third {
			return first
		}

		return third
	}

	if second < third {
		return second
	}

	return third
}

// getRegistry looks up a registry by domain from the plan's registry collection.
// Returns nil if no registry found (caller should handle as unauthenticated access).
// Logs a warning if domain not found, with typo suggestion if available.
func (plan *Plan) getRegistry(domain string) *Registry {
	normalizedDomain := normalizeDomain(domain)
	reg := plan.registries[normalizedDomain]

	if reg == nil {
		// Check for similar domains (typo detection)
		suggestion := plan.findSimilarDomain(normalizedDomain)

		if suggestion != "" {
			plan.log.Warn().
				Str("domain", normalizedDomain).
				Str("suggestion", suggestion).
				Msgf("Using anonymous access for registry (did you mean %s?)", suggestion)
		} else {
			plan.log.Warn().
				Str("domain", normalizedDomain).
				Msg("Using anonymous access for registry")
		}
	}

	return reg
}

// NewPlan creates a new Plan with the given name.
func NewPlan(name string) *Plan {
	return &Plan{
		name:       name,
		log:        log.Logger.With().Str("plan", name).Logger(),
		registries: make(map[string]*Registry),
	}
}

// Registry creates a new Registry builder.
func (plan *Plan) Registry(host string) *RegistryBuilder {
	return &RegistryBuilder{
		plan: plan,
		registry: &Registry{
			host: host,
			log:  plan.log.With().Str("registry", host).Logger(),
		},
	}
}

// BuildNode creates a new BuildNode builder.
func (plan *Plan) BuildNode(name string) *BuildNodeBuilder {
	return &BuildNodeBuilder{
		plan: plan,
		node: &BuildNode{
			name: name,
			log:  plan.log.With().Str("buildnode", name).Logger(),
		},
	}
}

// Sync creates a new Sync builder.
func (plan *Plan) Sync(name string) *SyncBuilder {
	return &SyncBuilder{
		plan: plan,
		sync: &Sync{
			opName: name,
			log:    plan.log.With().Str("sync", name).Logger(),
		},
	}
}

// Build creates a new Build builder.
func (plan *Plan) Build(name string) *BuildBuilder {
	return &BuildBuilder{
		plan: plan,
		build: &Build{
			opName: name,
			log:    plan.log.With().Str("build", name).Logger(),
		},
	}
}

// Scan creates a new Scan builder.
func (plan *Plan) Scan(name string) *ScanBuilder {
	return &ScanBuilder{
		plan: plan,
		scan: &Scan{
			opName: name,
			log:    plan.log.With().Str("scan", name).Logger(),
		},
	}
}

// Audit creates a new Audit builder.
func (plan *Plan) Audit(name string) *AuditBuilder {
	return &AuditBuilder{
		plan: plan,
		audit: &Audit{
			opName: name,
			log:    plan.log.With().Str("audit", name).Logger(),
		},
	}
}

// VersionCheck creates a new VersionCheck builder.
func (plan *Plan) VersionCheck(name string) *VersionCheckBuilder {
	return &VersionCheckBuilder{
		plan: plan,
		check: &VersionCheck{
			opName: name,
			log:    plan.log.With().Str("version_check", name).Logger(),
		},
	}
}

// executor implements plan execution logic.
type executor struct {
	plan    *Plan
	sshPool *ssh.Pool
}

// newExecutor creates a new plan executor.
func newExecutor(plan *Plan) *executor {
	sshPool := ssh.NewPool(plan.log)

	return &executor{
		plan:    plan,
		sshPool: sshPool,
	}
}

// Execute runs the plan with the given context.
func (plan *Plan) Execute(ctx context.Context) error {
	plan.log.Info().Msg("executing plan")

	// Create executor with SSH pool
	exec := newExecutor(plan)
	defer func() {
		if err := exec.sshPool.CloseAll(); err != nil {
			plan.log.Warn().Err(err).Msg("failed to close SSH connections")
		}
	}()

	// Set sshPool for all Build operations
	for _, build := range plan.builds {
		build.sshPool = exec.sshPool
	}

	// Execute all operations in the order they were added
	for _, op := range plan.operations {
		if err := op.execute(ctx); err != nil {
			return err
		}
	}

	plan.log.Info().Msg("plan execution complete")

	return nil
}

// DryRun simulates plan execution without making changes.
func (plan *Plan) DryRun() error {
	plan.log.Info().Msg("dry run (no changes will be made)")

	return nil
}
