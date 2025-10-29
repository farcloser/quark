package sdk

import "errors"

// 1Password errors.
var (
	// ErrDocumentReferenceEmpty indicates document reference is empty.
	ErrDocumentReferenceEmpty = errors.New("document reference cannot be empty")

	// ErrDocumentReferenceInvalidPrefix indicates document reference missing 'op://' prefix.
	ErrDocumentReferenceInvalidPrefix = errors.New("document reference must start with 'op://'")

	// ErrDocumentReferenceInvalidFormat indicates document reference has invalid format.
	ErrDocumentReferenceInvalidFormat = errors.New("invalid document reference format")

	// ErrDocumentReferenceEmptyParts indicates document reference has empty vault or item.
	ErrDocumentReferenceEmptyParts = errors.New("document reference vault and item cannot be empty")

	// ErrDocumentEmpty indicates document resolved to empty content.
	ErrDocumentEmpty = errors.New("document resolved to empty content")

	// ErrItemReferenceEmpty indicates item reference is empty.
	ErrItemReferenceEmpty = errors.New("item reference cannot be empty")

	// ErrItemReferenceInvalidPrefix indicates item reference missing 'op://' prefix.
	ErrItemReferenceInvalidPrefix = errors.New("item reference must start with 'op://'")

	// ErrItemReferenceInvalidFormat indicates item reference has invalid format.
	ErrItemReferenceInvalidFormat = errors.New("invalid item reference format")

	// ErrItemReferenceEmptyParts indicates item reference has empty vault or item.
	ErrItemReferenceEmptyParts = errors.New("item reference vault and item cannot be empty")

	// ErrItemFieldsEmpty indicates no fields requested for item retrieval.
	ErrItemFieldsEmpty = errors.New("fields list cannot be empty")

	// ErrItemFieldNotFound indicates requested field not found in item.
	ErrItemFieldNotFound = errors.New("field not found in item")
)

// Build errors.
var (
	// ErrNoBuildNodesConfigured indicates no build nodes were added to a build operation.
	ErrNoBuildNodesConfigured = errors.New("no build nodes configured")
)

// Scan errors.
var (
	// ErrScanMustHaveDigest indicates scan image requires digest specification.
	ErrScanMustHaveDigest = errors.New("scan image MUST have digest specified (scanning by tag alone is not allowed)")

	// ErrVulnerabilitiesFound indicates vulnerabilities were found at or above threshold.
	ErrVulnerabilitiesFound = errors.New("vulnerabilities found at or above threshold")
)

// Audit errors.
var (
	// ErrAuditFoundIssues indicates audit found issues.
	ErrAuditFoundIssues = errors.New("audit found issues")
)

// Version check errors.
var (
	// ErrDigestMismatch indicates digest mismatch detected.
	ErrDigestMismatch = errors.New("DIGEST MISMATCH (possible tag mutation or supply chain attack)")

	// ErrVersionCheckImageRequired indicates version check requires an image.
	ErrVersionCheckImageRequired = errors.New("version check image is required")

	// ErrVersionCheckVersionRequired indicates version check image must have version specified.
	ErrVersionCheckVersionRequired = errors.New("version check image must have version specified")
)

// Image errors.
var (
	// ErrImageNameRequired indicates image name is required.
	ErrImageNameRequired = errors.New("image name is required")

	// ErrImageVersionRequired indicates image version is required for tag reference.
	ErrImageVersionRequired = errors.New("cannot create tag reference without version")

	// ErrImageDigestRequired indicates image digest is required for digest reference.
	ErrImageDigestRequired = errors.New("cannot create digest reference without digest")
)

// Environment errors.
var (
	// ErrEnvVarNotSet indicates required environment variable is not set.
	ErrEnvVarNotSet = errors.New("required environment variable not set")
)

// BuildNode errors.
var (
	// ErrBuildNodeEndpointRequired indicates buildnode endpoint is required.
	ErrBuildNodeEndpointRequired = errors.New("buildnode endpoint is required")

	// ErrBuildNodePlatformRequired indicates buildnode platform is required.
	ErrBuildNodePlatformRequired = errors.New("buildnode platform is required")
)

// Sync errors.
var (
	// ErrSyncSourceRequired indicates sync source image is required.
	ErrSyncSourceRequired = errors.New("sync source image is required")

	// ErrSyncSourceDigestRequired indicates sync source image must have digest.
	ErrSyncSourceDigestRequired = errors.New(
		"sync source image MUST have digest specified (syncing by tag alone is not allowed)",
	)

	// ErrSyncDestinationRequired indicates sync destination image is required.
	ErrSyncDestinationRequired = errors.New("sync destination image is required")
)

// Build errors (additional).
var (
	// ErrBuildContextRequired indicates build context is required.
	ErrBuildContextRequired = errors.New("build context is required")

	// ErrBuildNodeRequired indicates at least one build node is required.
	ErrBuildNodeRequired = errors.New("at least one build node is required")

	// ErrBuildTagRequired indicates build tag is required.
	ErrBuildTagRequired = errors.New("build tag is required")
)

// Audit errors (additional).
var (
	// ErrAuditSourceRequired indicates audit requires either dockerfile or image.
	ErrAuditSourceRequired = errors.New("audit requires either dockerfile or image")
)

// Scan errors (additional).
var (
	// ErrScanImageRequired indicates scan image is required.
	ErrScanImageRequired = errors.New("scan image is required")

	// ErrInvalidScanSeverity indicates an invalid scan severity value.
	ErrInvalidScanSeverity = errors.New("invalid scan severity")

	// ErrInvalidScanAction indicates an invalid scan action value.
	ErrInvalidScanAction = errors.New("invalid scan action")

	// ErrInvalidScanFormat indicates an invalid scan format value.
	ErrInvalidScanFormat = errors.New("invalid scan format")
)

// Audit errors (JSON validation).
var (
	// ErrInvalidAuditRuleSet indicates an invalid audit rule set value.
	ErrInvalidAuditRuleSet = errors.New("invalid audit rule set")
)
