package sdk

import (
	"context"
	"sync/atomic"

	"github.com/farcloser/quark/dag"
)

// operationWrapper adapts an operation to the dag.Executable interface.
type operationWrapper struct {
	op       operation
	plan     *Plan // Set before execution for SSH pool access
	executed atomic.Bool
}

func (w *operationWrapper) Name() string {
	return w.op.operationName()
}

func (w *operationWrapper) Execute(ctx context.Context) error {
	// Set sshPool for build operations
	if b, ok := w.op.(*build); ok && w.plan != nil {
		b.sshPool = w.plan.sshPool
	}

	err := w.op.execute(ctx)
	if err == nil {
		w.executed.Store(true)
	}

	return err
}

// Handle provides fluent chaining for all operations.
// Any operation can be chained after any other operation.
type Handle struct {
	plan *Plan
	node *dag.Node[*operationWrapper]
	op   operation
}

// After adds dependencies on other operations.
// This handle's operation will not execute until all dependencies complete.
func (h *Handle) After(deps ...*Handle) *Handle {
	for _, dep := range deps {
		h.node.DependsOn(dep.node)
	}

	return h
}

// Build chains a build operation after this operation.
func (h *Handle) Build(args *BuildArgs) (*Handle, error) {
	handle, err := h.plan.Build(args)
	if err != nil {
		return nil, err
	}

	handle.node.DependsOn(h.node)

	return handle, nil
}

// Sync chains a sync operation after this operation.
func (h *Handle) Sync(args *SyncArgs) (*Handle, error) {
	handle, err := h.plan.Sync(args)
	if err != nil {
		return nil, err
	}

	handle.node.DependsOn(h.node)

	return handle, nil
}

// Scan chains a scan operation after this operation.
func (h *Handle) Scan(args *ScanArgs) (*Handle, error) {
	handle, err := h.plan.Scan(args)
	if err != nil {
		return nil, err
	}

	handle.node.DependsOn(h.node)

	return handle, nil
}

// Audit chains an audit operation after this operation.
func (h *Handle) Audit(args *AuditArgs) (*Handle, error) {
	handle, err := h.plan.Audit(args)
	if err != nil {
		return nil, err
	}

	handle.node.DependsOn(h.node)

	return handle, nil
}

// CheckVersion chains a version check operation after this operation.
func (h *Handle) CheckVersion(name string, source *Image, force bool) (*Handle, error) {
	handle, err := h.plan.CheckVersion(name, source, force)
	if err != nil {
		return nil, err
	}

	handle.node.DependsOn(h.node)

	return handle, nil
}

// VersionCheckResult returns the result of a version check operation.
// Returns nil if this handle is not a version check operation or if not yet executed.
func (h *Handle) VersionCheckResult() *VersionCheckResult {
	versionCheck, ok := h.op.(*versionCheckOp)
	if !ok {
		return nil
	}

	if !h.node.Executable().executed.Load() {
		h.plan.log.Warn().Str("operation", versionCheck.opName).Msg("accessing version check result before execution")

		return nil
	}

	return &VersionCheckResult{
		CurrentVersion:  versionCheck.currentVersion,
		LatestVersion:   versionCheck.latestVersion,
		LatestDigest:    versionCheck.latestDigest,
		UpdateAvailable: versionCheck.updateAvailable,
	}
}
