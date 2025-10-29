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
)
