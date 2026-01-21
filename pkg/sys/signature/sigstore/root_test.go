package sigstore_test

import (
	"errors"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/farcloser/quark/pkg/fault"
	"github.com/farcloser/quark/pkg/sys/signature/sigstore"
)

// Minimal valid TrustedRoot JSON structure.
// This is the minimum required for sigstore-go to parse without error.
const validTrustedRootJSON = `{
	"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
	"tlogs": [],
	"certificateAuthorities": [],
	"ctlogs": [],
	"timestampAuthorities": []
}`

func TestNewRoot_EmptyString(t *testing.T) {
	t.Parallel()

	root := sigstore.NewRoot("")

	assert.Assert(t, root != nil, "NewRoot should return non-nil Root")
	assert.Assert(t, root.Get() == nil, "Get() should return nil when initialized with empty string")
}

func TestNewRoot_ValidJSON(t *testing.T) {
	t.Parallel()

	root := sigstore.NewRoot(validTrustedRootJSON)

	assert.Assert(t, root != nil, "NewRoot should return non-nil Root")
	assert.Assert(t, root.Get() != nil, "Get() should return non-nil TrustedRoot when initialized with valid JSON")
}

func TestNewRoot_InvalidJSON(t *testing.T) {
	t.Parallel()

	// NewRoot ignores errors from FromBytes, so it should return a Root with nil internal root.
	root := sigstore.NewRoot("not valid json {{{")

	assert.Assert(t, root != nil, "NewRoot should return non-nil Root even with invalid JSON")
	assert.Assert(t, root.Get() == nil, "Get() should return nil when initialized with invalid JSON")
}

func TestNewRoot_WrongStructure(t *testing.T) {
	t.Parallel()

	// Valid JSON but wrong structure for TrustedRoot.
	// Go's json.Unmarshal is lenient: unknown fields ignored, missing fields get zero values.
	// This will parse into an empty TrustedRoot with no tlogs, CAs, etc.
	root := sigstore.NewRoot(`{"foo": "bar"}`)

	assert.Assert(t, root != nil, "NewRoot should return non-nil Root")
	assert.Assert(t, root.Get() != nil, "Get() should return non-nil TrustedRoot (empty but valid)")
}

func TestFromBytes_ValidJSON(t *testing.T) {
	t.Parallel()

	root := sigstore.NewRoot("")
	err := root.FromBytes([]byte(validTrustedRootJSON))

	assert.NilError(t, err, "FromBytes should succeed with valid JSON")
	assert.Assert(t, root.Get() != nil, "Get() should return non-nil after successful FromBytes")
}

func TestFromBytes_InvalidJSON_ReturnsSentinelError(t *testing.T) {
	t.Parallel()

	root := sigstore.NewRoot("")
	err := root.FromBytes([]byte("not valid json {{{"))

	assert.Assert(t, err != nil, "FromBytes should return error for invalid JSON")
	assert.Assert(t, errors.Is(err, fault.ErrInvalidArgument),
		"error should wrap fault.ErrInvalidArgument, got: %v", err)
}

func TestFromBytes_EmptyData_ReturnsSentinelError(t *testing.T) {
	t.Parallel()

	root := sigstore.NewRoot("")
	err := root.FromBytes([]byte{})

	assert.Assert(t, err != nil, "FromBytes should return error for empty data")
	assert.Assert(t, errors.Is(err, fault.ErrInvalidArgument),
		"error should wrap fault.ErrInvalidArgument, got: %v", err)
}

func TestFromBytes_NilData_ReturnsSentinelError(t *testing.T) {
	t.Parallel()

	root := sigstore.NewRoot("")
	err := root.FromBytes(nil)

	assert.Assert(t, err != nil, "FromBytes should return error for nil data")
	assert.Assert(t, errors.Is(err, fault.ErrInvalidArgument),
		"error should wrap fault.ErrInvalidArgument, got: %v", err)
}

func TestFromBytes_WrongStructure_Succeeds(t *testing.T) {
	t.Parallel()

	root := sigstore.NewRoot("")
	// Valid JSON but wrong structure for TrustedRoot.
	// Go's json.Unmarshal is lenient: unknown fields ignored, missing fields get zero values.
	// This parses into an empty TrustedRoot with no tlogs, CAs, etc.
	err := root.FromBytes([]byte(`{"random": "object"}`))

	assert.NilError(t, err, "FromBytes should succeed with valid JSON (lenient parsing)")
	assert.Assert(t, root.Get() != nil, "Get() should return non-nil TrustedRoot (empty but valid)")
}

func TestFromBytes_OverwritesPreviousRoot(t *testing.T) {
	t.Parallel()

	root := sigstore.NewRoot(validTrustedRootJSON)
	originalPtr := root.Get()
	assert.Assert(t, originalPtr != nil, "initial root should be set")

	// Overwrite with new data - creates new allocation.
	err := root.FromBytes([]byte(validTrustedRootJSON))
	assert.NilError(t, err)

	newPtr := root.Get()
	assert.Assert(t, newPtr != nil, "root should be set after overwrite")
	assert.Assert(t, newPtr != originalPtr, "FromBytes should replace root, not keep original")
}

func TestFromBytes_FailureDoesNotClearPreviousRoot(t *testing.T) {
	t.Parallel()

	root := sigstore.NewRoot(validTrustedRootJSON)
	originalRoot := root.Get()
	assert.Assert(t, originalRoot != nil, "initial root should be set")

	// Attempt to overwrite with invalid data.
	err := root.FromBytes([]byte("invalid"))
	assert.Assert(t, err != nil, "FromBytes should fail with invalid data")

	// Original root should be preserved.
	assert.Equal(t, root.Get(), originalRoot, "original root should be preserved after failed FromBytes")
}

// TestFromNetwork_Integration tests network fetching of the TrustedRoot.
// This test requires network access and is skipped by default.
// Run with: go test -run TestFromNetwork_Integration -tags=integration.
func TestFromNetwork_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	t.Parallel()

	root := sigstore.NewRoot("")
	err := root.FromNetwork()

	assert.NilError(t, err, "FromNetwork should succeed with network access")
	assert.Assert(t, root.Get() != nil, "Get() should return non-nil after FromNetwork")

	// Verify the fetched root has expected structure.
	trusted := root.Get()
	assert.Assert(t, trusted != nil, "TrustedRoot should not be nil")
}
