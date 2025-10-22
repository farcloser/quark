package sdk

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/ssh"
)

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
}

// normalizeDomain normalizes a registry domain.
// Empty string is normalized to "docker.io" (Docker Hub default).
func normalizeDomain(domain string) string {
	if domain == "" {
		return "docker.io"
	}

	return domain
}

// getRegistry looks up a registry by domain from the plan's registry collection.
// Returns nil if no registry found (caller should handle as unauthenticated access).
func (plan *Plan) getRegistry(domain string) *Registry {
	normalizedDomain := normalizeDomain(domain)

	return plan.registries[normalizedDomain]
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
			name: name,
			log:  plan.log.With().Str("sync", name).Logger(),
		},
	}
}

// Build creates a new Build builder.
func (plan *Plan) Build(name string) *BuildBuilder {
	return &BuildBuilder{
		plan: plan,
		build: &Build{
			name: name,
			log:  plan.log.With().Str("build", name).Logger(),
		},
	}
}

// Scan creates a new Scan builder.
func (plan *Plan) Scan(name string) *ScanBuilder {
	return &ScanBuilder{
		plan: plan,
		scan: &Scan{
			name: name,
			log:  plan.log.With().Str("scan", name).Logger(),
		},
	}
}

// Audit creates a new Audit builder.
func (plan *Plan) Audit(name string) *AuditBuilder {
	return &AuditBuilder{
		plan: plan,
		audit: &Audit{
			name: name,
			log:  plan.log.With().Str("audit", name).Logger(),
		},
	}
}

// VersionCheck creates a new VersionCheck builder.
func (plan *Plan) VersionCheck(name string) *VersionCheckBuilder {
	return &VersionCheckBuilder{
		plan: plan,
		check: &VersionCheck{
			name: name,
			log:  plan.log.With().Str("version_check", name).Logger(),
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

	// Execute in order: version checks → syncs → builds → scans → audits
	if err := exec.executeVersionChecks(ctx); err != nil {
		return err
	}

	if err := exec.executeSyncs(ctx); err != nil {
		return err
	}

	if err := exec.executeBuilds(ctx); err != nil {
		return err
	}

	if err := exec.executeScans(ctx); err != nil {
		return err
	}

	if err := exec.executeAudits(ctx); err != nil {
		return err
	}

	plan.log.Info().Msg("plan execution complete")

	return nil
}

// DryRun simulates plan execution without making changes.
func (plan *Plan) DryRun() error {
	plan.log.Info().Msg("dry run (no changes will be made)")

	return nil
}

func (e *executor) executeSyncs(ctx context.Context) error {
	for _, sync := range e.plan.syncs {
		if err := sync.execute(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (e *executor) executeBuilds(ctx context.Context) error {
	for _, build := range e.plan.builds {
		if err := build.execute(ctx, e.sshPool); err != nil {
			return err
		}
	}

	return nil
}

func (e *executor) executeScans(ctx context.Context) error {
	for _, scan := range e.plan.scans {
		if err := scan.execute(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (e *executor) executeAudits(ctx context.Context) error {
	for _, audit := range e.plan.audits {
		if err := audit.execute(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (e *executor) executeVersionChecks(ctx context.Context) error {
	for _, check := range e.plan.versionChecks {
		if err := check.execute(ctx); err != nil {
			return err
		}
	}

	return nil
}
