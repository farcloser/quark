package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

const (
	testPlanName        = "test-plan"
	testDomain          = "docker.io"
	testVersion         = "1.0.0"
	testDigest          = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	errFirstBuildMsg    = "first Build() failed: %v"
	errExpectedReuseMsg = "expected ErrBuilderAlreadyUsed, got: %v"
)

// TestImageBuilder_ReuseReturnsError verifies ImageBuilder cannot be reused after Build().
func TestImageBuilder_ReuseReturnsError(t *testing.T) {
	t.Parallel()

	builder := sdk.NewImage("test/image")
	builder.Domain(testDomain)
	builder.Version(testVersion)

	// First build succeeds
	_, err := builder.Build()
	if err != nil {
		t.Fatalf(errFirstBuildMsg, err)
	}

	// Second build fails with sdk.ErrBuilderAlreadyUsed
	_, err = builder.Build()
	if !errors.Is(err, sdk.ErrBuilderAlreadyUsed) {
		t.Errorf(errExpectedReuseMsg, err)
	}
}

// TestRegistryBuilder_ReuseReturnsError verifies RegistryBuilder cannot be reused after Build().
func TestRegistryBuilder_ReuseReturnsError(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan(testPlanName)
	builder := plan.Registry(testDomain)
	builder.Username("testuser")
	builder.Password("testpass")

	// First build succeeds
	_, err := builder.Build()
	if err != nil {
		t.Fatalf(errFirstBuildMsg, err)
	}

	// Second build fails with sdk.ErrBuilderAlreadyUsed
	_, err = builder.Build()
	if !errors.Is(err, sdk.ErrBuilderAlreadyUsed) {
		t.Errorf(errExpectedReuseMsg, err)
	}
}

// TestBuildNodeBuilder_ReuseReturnsError verifies BuildNodeBuilder cannot be reused after Build().
func TestBuildNodeBuilder_ReuseReturnsError(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan(testPlanName)
	builder := plan.BuildNode("test-node")
	builder.Endpoint("build-server")
	builder.Platform(sdk.PlatformAMD64)

	// First build succeeds
	_, err := builder.Build()
	if err != nil {
		t.Fatalf(errFirstBuildMsg, err)
	}

	// Second build fails with sdk.ErrBuilderAlreadyUsed
	_, err = builder.Build()
	if !errors.Is(err, sdk.ErrBuilderAlreadyUsed) {
		t.Errorf(errExpectedReuseMsg, err)
	}
}

// TestBuildBuilder_ReuseReturnsError verifies BuildBuilder cannot be reused after Build().
func TestBuildBuilder_ReuseReturnsError(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan(testPlanName)
	node, _ := plan.BuildNode("test-node").
		Endpoint("build-server").
		Platform(sdk.PlatformAMD64).
		Build()

	builder := plan.Build("test-build")
	builder.Context("/tmp/context")
	builder.Node(node)
	builder.Tag("test:latest")

	// First build succeeds
	_, err := builder.Build()
	if err != nil {
		t.Fatalf(errFirstBuildMsg, err)
	}

	// Second build fails with sdk.ErrBuilderAlreadyUsed
	_, err = builder.Build()
	if !errors.Is(err, sdk.ErrBuilderAlreadyUsed) {
		t.Errorf(errExpectedReuseMsg, err)
	}
}

// TestScanBuilder_ReuseReturnsError verifies ScanBuilder cannot be reused after Build().
func TestScanBuilder_ReuseReturnsError(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan(testPlanName)
	img, _ := sdk.NewImage("test/image").
		Domain(testDomain).
		Version(testVersion).
		Digest(testDigest).
		Build()

	builder := plan.Scan("test-scan")
	builder.Source(img)

	// First build succeeds
	_, err := builder.Build()
	if err != nil {
		t.Fatalf(errFirstBuildMsg, err)
	}

	// Second build fails with sdk.ErrBuilderAlreadyUsed
	_, err = builder.Build()
	if !errors.Is(err, sdk.ErrBuilderAlreadyUsed) {
		t.Errorf(errExpectedReuseMsg, err)
	}
}

// TestAuditBuilder_ReuseReturnsError verifies AuditBuilder cannot be reused after Build().
func TestAuditBuilder_ReuseReturnsError(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan(testPlanName)
	img, _ := sdk.NewImage("test/image").
		Domain(testDomain).
		Version(testVersion).
		Build()

	builder := plan.Audit("test-audit")
	builder.Source(img)

	// First build succeeds
	_, err := builder.Build()
	if err != nil {
		t.Fatalf(errFirstBuildMsg, err)
	}

	// Second build fails with sdk.ErrBuilderAlreadyUsed
	_, err = builder.Build()
	if !errors.Is(err, sdk.ErrBuilderAlreadyUsed) {
		t.Errorf(errExpectedReuseMsg, err)
	}
}

// TestSyncBuilder_ReuseReturnsError verifies SyncBuilder cannot be reused after Build().
func TestSyncBuilder_ReuseReturnsError(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan(testPlanName)
	srcImg, _ := sdk.NewImage("test/source").
		Domain(testDomain).
		Version(testVersion).
		Digest(testDigest).
		Build()

	destImg, _ := sdk.NewImage("test/dest").
		Domain("ghcr.io").
		Version(testVersion).
		Build()

	builder := plan.Sync("test-sync")
	builder.Source(srcImg)
	builder.Destination(destImg)

	// First build succeeds
	_, err := builder.Build()
	if err != nil {
		t.Fatalf(errFirstBuildMsg, err)
	}

	// Second build fails with sdk.ErrBuilderAlreadyUsed
	_, err = builder.Build()
	if !errors.Is(err, sdk.ErrBuilderAlreadyUsed) {
		t.Errorf(errExpectedReuseMsg, err)
	}
}

// TestVersionCheckBuilder_ReuseReturnsError verifies VersionCheckBuilder cannot be reused after Build().
func TestVersionCheckBuilder_ReuseReturnsError(t *testing.T) {
	t.Parallel()

	plan := sdk.NewPlan(testPlanName)
	img, _ := sdk.NewImage("test/image").
		Domain(testDomain).
		Version(testVersion).
		Build()

	builder := plan.VersionCheck("test-version-check")
	builder.Source(img)

	// First build succeeds
	_, err := builder.Build()
	if err != nil {
		t.Fatalf(errFirstBuildMsg, err)
	}

	// Second build fails with sdk.ErrBuilderAlreadyUsed
	_, err = builder.Build()
	if !errors.Is(err, sdk.ErrBuilderAlreadyUsed) {
		t.Errorf(errExpectedReuseMsg, err)
	}
}

// TestBuilderReuse_AfterValidationError verifies builders remain unusable even after validation errors.
func TestBuilderReuse_AfterValidationError(t *testing.T) {
	t.Parallel()

	t.Run("ImageBuilder with empty name", func(t *testing.T) {
		t.Parallel()

		builder := sdk.NewImage("") // Empty name will fail validation

		// First build fails with validation error
		_, err := builder.Build()
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}

		if !errors.Is(err, sdk.ErrImageNameRequired) {
			t.Errorf("expected sdk.ErrImageNameRequired, got: %v", err)
		}

		// Second build also fails with sdk.ErrBuilderAlreadyUsed (not validation error)
		_, err = builder.Build()
		if !errors.Is(err, sdk.ErrBuilderAlreadyUsed) {
			t.Errorf("expected sdk.ErrBuilderAlreadyUsed after validation failure, got: %v", err)
		}
	})

	t.Run("SyncBuilder without digest", func(t *testing.T) {
		t.Parallel()

		plan := sdk.NewPlan(testPlanName)
		srcImg, _ := sdk.NewImage("test/source").
			Domain(testDomain).
			Version(testVersion).
			Build() // No digest - will fail sync validation

		builder := plan.Sync("test-sync")
		builder.Source(srcImg)

		// First build fails with validation error
		_, err := builder.Build()
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}

		if !errors.Is(err, sdk.ErrSyncSourceDigestRequired) {
			t.Errorf("expected sdk.ErrSyncSourceDigestRequired, got: %v", err)
		}

		// Second build also fails with sdk.ErrBuilderAlreadyUsed
		_, err = builder.Build()
		if !errors.Is(err, sdk.ErrBuilderAlreadyUsed) {
			t.Errorf("expected sdk.ErrBuilderAlreadyUsed after validation failure, got: %v", err)
		}
	})
}

// TestBuilderReuse_ImmutabilityCheck verifies that modifying builder fields after Build() doesn't affect returned
// object.
func TestBuilderReuse_ImmutabilityCheck(t *testing.T) {
	t.Parallel()

	builder := sdk.NewImage("test/image")
	builder.Domain(testDomain)
	builder.Version(testVersion)

	// First build succeeds
	img1, err := builder.Build()
	if err != nil {
		t.Fatalf(errFirstBuildMsg, err)
	}

	originalVersion := img1.Version()
	if originalVersion != testVersion {
		t.Fatalf("expected version %s, got: %s", testVersion, originalVersion)
	}

	// Try to modify builder (even though it's already built)
	builder.Version("2.0.0")

	// Original image should be unchanged (immutability)
	if img1.Version() != originalVersion {
		t.Errorf("image was mutated after Build(): expected %s, got %s", originalVersion, img1.Version())
	}
}
