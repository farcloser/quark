package sdk

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/dag"
	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/internal/registry"
	"github.com/farcloser/quark/ssh"
)

// operation is an internal interface for all executable operations.
// This interface enables unified operation handling and simplifies adding new operation types.
type operation interface {
	execute(ctx context.Context) error
	operationName() string
}

// Plan represents a declarative container image management plan.
// Operations are organized in a DAG for parallel execution of independent operations.
type Plan struct {
	name string
	log  zerolog.Logger

	// Resources
	registries map[string]*Registry // keyed by normalized domain
	buildNodes []*BuildNode

	// Trusted signers for signature verification
	trustedSigners []SignerIdentity

	// Operation DAG for dependency-based parallel execution
	graph   *dag.Graph[*operationWrapper]
	nodeSeq atomic.Uint64

	// SSH pool shared across Build operations
	sshPool *ssh.Pool
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
		graph:      dag.NewGraph[*operationWrapper](),
	}
}

// nextNodeID generates a unique node ID for the DAG.
func (plan *Plan) nextNodeID(prefix string) string {
	seq := plan.nodeSeq.Add(1)

	return fmt.Sprintf("%s-%d", prefix, seq)
}

// AddRegistry attaches an existing registry to the plan.
// The registry's host is used as the key for credential lookup during operations.
func (plan *Plan) AddRegistry(reg *Registry) {
	plan.registries[reg.domain] = reg
}

// TrustSigner adds a signer identity to the global trusted signers list.
// Images without per-image SignedBy will be verified against these signers.
func (plan *Plan) TrustSigner(signer SignerIdentity) {
	plan.trustedSigners = append(plan.trustedSigners, signer)
	plan.log.Debug().
		Str("subject", signer.Subject).
		Str("issuer", signer.Issuer).
		Msg("added trusted signer")
}

// AddBuildNode attaches an existing build node to the plan.
func (plan *Plan) AddBuildNode(node *BuildNode) {
	plan.buildNodes = append(plan.buildNodes, node)
}

// GetDigest returns the digest for an image from its registry.
// The registry credentials are automatically looked up by image domain.
func (plan *Plan) GetDigest(ctx context.Context, image *Image) (string, error) {
	reg := plan.getRegistry(image.Domain())

	var username, token string
	if reg != nil {
		username = reg.username
		token = reg.token
	}

	client := registry.NewClient(image.Domain(), username, token, plan.log)

	//nolint:wrapcheck
	return client.GetDigest(ctx, image.tagRef())
}

// ListTags returns all tags for an image repository.
// The registry credentials are automatically looked up by image domain.
func (plan *Plan) ListTags(ctx context.Context, image *Image) ([]string, error) {
	reg := plan.getRegistry(image.Domain())

	var username, token string
	if reg != nil {
		username = reg.username
		token = reg.token
	}

	client := registry.NewClient(image.Domain(), username, token, plan.log)
	repository := image.Domain() + "/" + image.Path()

	//nolint:wrapcheck
	return client.ListTags(ctx, repository)
}

// Sync creates a sync operation and registers it with the plan.
// Returns a handle for chaining additional operations.
//
// The source image must have at least a tag or digest:
//   - Tag only: Resolves to digest, verifies signature
//   - Digest only: Verifies signature on digest
//   - Tag + Digest: Verifies signature, detects tag drift
//   - InsecureNoSignature: Skips verification (not recommended)
func (plan *Plan) Sync(args *SyncArgs) (*Handle, error) {
	if args.Source == nil {
		return nil, ErrSyncSourceRequired
	}

	// Validate that at least tag or digest is specified.
	if args.Source.Version() == "" && args.Source.Digest() == "" {
		return nil, ErrMustSpecifyTagOrDigest
	}

	if args.Destination == nil {
		return nil, ErrSyncDestinationRequired
	}

	platforms := args.Platforms
	if len(platforms) == 0 {
		platforms = []Platform{PlatformAMD64, PlatformARM64}
	}

	syncOperation := &syncOp{
		opName:         args.Description,
		sourceImage:    args.Source,
		sourceRegistry: plan.getRegistry(args.Source.Domain()),
		destImage:      args.Destination,
		destRegistry:   plan.getRegistry(args.Destination.Domain()),
		platforms:      platforms,
		trustedSigners: plan.trustedSigners,
		log:            plan.log.With().Str("sync", args.Description).Logger(),
	}

	wrapper := &operationWrapper{op: syncOperation}
	node := dag.NewNode(plan.nextNodeID("sync"), wrapper)
	plan.graph.Add(node)

	return &Handle{plan: plan, node: node, op: syncOperation}, nil
}

// Build creates a build operation and registers it with the plan.
// Returns a handle for chaining additional operations.
func (plan *Plan) Build(args *BuildArgs) (*Handle, error) {
	if args.Context == "" {
		return nil, ErrBuildContextRequired
	}

	if len(args.Nodes) == 0 {
		return nil, ErrBuildNodeRequired
	}

	if args.Tag == "" {
		return nil, ErrBuildTagRequired
	}

	dockerfile := args.Dockerfile
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}

	// Parse tag to extract registry domain for authentication
	var destRegistry *Registry

	tagRef, err := reference.Parse(args.Tag)
	if err == nil && tagRef.Domain != "" {
		destRegistry = plan.getRegistry(tagRef.Domain)
	}

	buildOp := &build{
		opName:       args.Name,
		context:      args.Context,
		dockerfile:   dockerfile,
		nodes:        args.Nodes,
		tag:          args.Tag,
		timeout:      args.Timeout,
		destRegistry: destRegistry,
		log:          plan.log.With().Str("build", args.Name).Logger(),
	}

	wrapper := &operationWrapper{op: buildOp}
	node := dag.NewNode(plan.nextNodeID("build"), wrapper)
	plan.graph.Add(node)

	return &Handle{plan: plan, node: node, op: buildOp}, nil
}

// Scan creates a scan operation and registers it with the plan.
// Returns a handle for chaining additional operations.
func (plan *Plan) Scan(args *ScanArgs) (*Handle, error) {
	if args.Source == nil {
		return nil, ErrScanImageRequired
	}

	severityChecks := args.SeverityChecks
	if len(severityChecks) == 0 {
		severityChecks = []ScanSeverityCheck{
			{Threshold: SeverityHigh, Action: ActionError},
			{Threshold: SeverityCritical, Action: ActionError},
		}
	}

	format := args.Format
	if format == nil {
		format = FormatTable
	}

	scanOperation := &scanOp{
		opName:         args.Description,
		image:          args.Source,
		registry:       plan.getRegistry(args.Source.Domain()),
		severityChecks: severityChecks,
		format:         format,
		timeout:        args.Timeout,
		log:            plan.log.With().Str("scan", args.Description).Logger(),
	}

	wrapper := &operationWrapper{op: scanOperation}
	node := dag.NewNode(plan.nextNodeID("scan"), wrapper)
	plan.graph.Add(node)

	return &Handle{plan: plan, node: node, op: scanOperation}, nil
}

// Audit creates an audit operation and registers it with the plan.
// Returns a handle for chaining additional operations.
func (plan *Plan) Audit(args *AuditArgs) (*Handle, error) {
	if args.Dockerfile == "" && args.Source == nil {
		return nil, ErrAuditSourceRequired
	}

	ruleSet := args.RuleSet
	if ruleSet == (AuditRuleSet{}) {
		ruleSet = RuleSetStrict
	}

	auditOperation := &auditOp{
		opName:       args.Description,
		dockerfile:   args.Dockerfile,
		image:        args.Source,
		ruleSet:      ruleSet,
		ignoreChecks: args.IgnoreChecks,
		timeout:      args.Timeout,
		log:          plan.log.With().Str("audit", args.Description).Logger(),
	}

	if args.Source != nil {
		auditOperation.registry = plan.getRegistry(args.Source.Domain())
	}

	wrapper := &operationWrapper{op: auditOperation}
	node := dag.NewNode(plan.nextNodeID("audit"), wrapper)
	plan.graph.Add(node)

	return &Handle{plan: plan, node: node, op: auditOperation}, nil
}

// CheckVersion creates a version check operation and registers it with the plan.
// Returns a handle for chaining additional operations.
func (plan *Plan) CheckVersion(name string, source *Image, force bool) (*Handle, error) {
	if source == nil {
		return nil, ErrVersionCheckImageRequired
	}

	version := source.Version()
	if version == "" {
		return nil, ErrVersionCheckVersionRequired
	}

	if version == "latest" {
		return nil, ErrVersionCheckLatestNotSupported
	}

	checkOperation := &versionCheckOp{
		opName:   name,
		image:    source,
		registry: plan.getRegistry(source.Domain()),
		force:    force,
		log:      plan.log.With().Str("version_check", name).Logger(),
	}

	wrapper := &operationWrapper{op: checkOperation}
	node := dag.NewNode(plan.nextNodeID("version_check"), wrapper)
	plan.graph.Add(node)

	return &Handle{plan: plan, node: node, op: checkOperation}, nil
}

// Execute runs the plan with the given context.
// Operations are executed in parallel where dependencies allow.
func (plan *Plan) Execute(ctx context.Context) error {
	plan.log.Info().Msg("executing plan")

	// Initialize SSH pool for Build operations
	plan.sshPool = ssh.NewPool(plan.log)
	defer func() {
		if err := plan.sshPool.CloseAll(); err != nil {
			plan.log.Warn().Err(err).Msg("failed to close SSH connections")
		}
	}()

	// Set SSH pool and context on all operation wrappers before execution
	for _, node := range plan.graph.Nodes() {
		wrapper := node.Executable()
		wrapper.plan = plan
	}

	// Execute the DAG (handles parallelism and dependencies)
	if err := plan.graph.Execute(ctx); err != nil {
		return fmt.Errorf("plan execution failed: %w", err)
	}

	plan.log.Info().Msg("plan execution complete")

	return nil
}

// DryRun simulates plan execution without making changes.
func (plan *Plan) DryRun() error {
	plan.log.Info().Msg("dry run (no changes will be made)")

	return nil
}
