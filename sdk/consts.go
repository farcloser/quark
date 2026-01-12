package sdk

// Used by logging to prepend to actions.
const (
	actionCreateName      = "create"
	actionBuildName       = "build"
	actionCheckName       = "check"
	actionLogName         = "log"
	actionLintName        = "lint"
	actionScanName        = "scan"
	actionAuditName       = "audit"
	actionSyncName        = "sync"
	actionSignName        = "sign"
	actionAttestName      = "attest"
	actionCopyName        = "copy"
	actionUpdateName      = "update"
	actionDoName          = "do"
	actionExportName      = "export"
	signerResourceName    = "signer"
	builderResourceName   = "builder"
	imageResourceName     = "image"
	directoryResourceName = "directory"
	registryResourceName  = "registry"
	nodeResourceName      = "node"
)

const (
	// If not provided when creating a registry, domain will default to this.
	defaultRegistry = "docker.io"
	// Default number of concurrent builds allowed per-node.
	defaultNodeConcurrency = 1
)
