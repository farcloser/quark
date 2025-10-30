package sdk_test

import (
	"log"

	"github.com/farcloser/quark/sdk"
)

// Example_buildImage demonstrates building a multi-platform container image.
func Example_buildImage() {
	// Create a plan
	plan := sdk.NewPlan("my-build-plan")

	// Configure build nodes for each platform
	amd64Node, err := plan.BuildNode("amd64-builder").
		Endpoint("user@amd64-builder.example.com").
		Platform(sdk.PlatformAMD64).
		Build()
	if err != nil {
		log.Fatal(err)
	}

	arm64Node, err := plan.BuildNode("arm64-builder").
		Endpoint("user@arm64-builder.example.com").
		Platform(sdk.PlatformARM64).
		Build()
	if err != nil {
		log.Fatal(err)
	}

	// Build multi-platform image
	_, err = plan.Build("my-app").
		Context("./app").
		Dockerfile("Dockerfile").
		Tag("ghcr.io/myorg/myapp:v1.0.0").
		Node(amd64Node).
		Node(arm64Node).
		Build()
	if err != nil {
		log.Fatal(err)
	}
	// Output:
}

// Example_syncImage demonstrates syncing an image between registries.
func Example_syncImage() {
	// Create a plan
	plan := sdk.NewPlan("sync-plan")

	// Configure source registry (Docker Hub)
	_, err := plan.Registry("docker.io").
		Username("sourceuser").
		Password("sourcepass").
		Build()
	if err != nil {
		log.Fatal(err)
	}

	// Configure destination registry (GitHub Container Registry)
	_, err = plan.Registry("ghcr.io").
		Username("destuser").
		Password("destpass").
		Build()
	if err != nil {
		log.Fatal(err)
	}

	// Create source image reference with digest (required for security)
	sourceImage, err := sdk.NewImage("library/alpine").
		Version("3.20").
		Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").
		Build()
	if err != nil {
		log.Fatal(err)
	}

	// Create destination image reference
	destImage, err := sdk.NewImage("myorg/alpine").
		Domain("ghcr.io").
		Version("3.20").
		Build()
	if err != nil {
		log.Fatal(err)
	}

	// Sync the image
	_, err = plan.Sync("alpine-sync").
		Source(sourceImage).
		Destination(destImage).
		Build()
	if err != nil {
		log.Fatal(err)
	}
	// Output:
}

// Example_scanImage demonstrates scanning an image for vulnerabilities.
func Example_scanImage() {
	// Create a plan
	plan := sdk.NewPlan("scan-plan")

	// Configure registry
	_, err := plan.Registry("ghcr.io").
		Username("user").
		Password("pass").
		Build()
	if err != nil {
		log.Fatal(err)
	}

	// Create image reference with digest
	image, err := sdk.NewImage("myorg/myapp").
		Domain("ghcr.io").
		Version("v1.0.0").
		Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").
		Build()
	if err != nil {
		log.Fatal(err)
	}

	// Scan for HIGH and CRITICAL vulnerabilities
	_, err = plan.Scan("security-scan").
		Source(image).
		Severity(sdk.SeverityHigh).
		Severity(sdk.SeverityCritical).
		Format(sdk.FormatTable).
		Build()
	if err != nil {
		log.Fatal(err)
	}
	// Output:
}

// Example_auditImage demonstrates auditing a Dockerfile and container image.
func Example_auditImage() {
	// Create a plan
	plan := sdk.NewPlan("audit-plan")

	// Configure registry
	_, err := plan.Registry("ghcr.io").
		Username("user").
		Password("pass").
		Build()
	if err != nil {
		log.Fatal(err)
	}

	// Create image reference
	image, err := sdk.NewImage("myorg/myapp").
		Domain("ghcr.io").
		Version("v1.0.0").
		Build()
	if err != nil {
		log.Fatal(err)
	}

	// Audit Dockerfile and image with strict rules
	_, err = plan.Audit("security-audit").
		Dockerfile("./Dockerfile").
		Source(image).
		RuleSet(sdk.RuleSetStrict).
		IgnoreChecks("DKL-DI-0005"). // Ignore specific check
		Build()
	if err != nil {
		log.Fatal(err)
	}
	// Output:
}

// Example_versionCheck demonstrates checking for image version updates.
func Example_versionCheck() {
	// Create a plan
	plan := sdk.NewPlan("version-check-plan")

	// Configure registry
	_, err := plan.Registry("docker.io").
		Username("user").
		Password("pass").
		Build()
	if err != nil {
		log.Fatal(err)
	}

	// Create image reference with current digest
	image, err := sdk.NewImage("library/alpine").
		Version("3.20").
		Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").
		Build()
	if err != nil {
		log.Fatal(err)
	}

	// Check if tag points to a different digest (version update available)
	_, err = plan.VersionCheck("alpine-version-check").
		Source(image).
		Build()
	if err != nil {
		log.Fatal(err)
	}
	// Output:
}

// Example_completeWorkflow demonstrates a complete CI/CD workflow combining multiple operations.
func Example_completeWorkflow() {
	// Create a plan that builds, audits, scans, and syncs an image
	plan := sdk.NewPlan("complete-workflow")

	// Configure registries
	_, _ = plan.Registry("staging.example.com").
		Username("stg-user").
		Password("stg-pass").
		Build()

	_, _ = plan.Registry("ghcr.io").
		Username("prod-user").
		Password("prod-pass").
		Build()

	// Configure build nodes
	amd64Node, _ := plan.BuildNode("amd64-builder").
		Endpoint("user@builder.example.com").
		Platform(sdk.PlatformAMD64).
		Build()

	arm64Node, _ := plan.BuildNode("arm64-builder").
		Endpoint("user@arm-builder.example.com").
		Platform(sdk.PlatformARM64).
		Build()

	// Step 1: Build image
	_, _ = plan.Build("build-app").
		Context("./app").
		Dockerfile("Dockerfile").
		Tag("staging.example.com/myapp:v1.0.0").
		Node(amd64Node).
		Node(arm64Node).
		Build()

	// Step 2: Audit Dockerfile and built image
	stagingImage, _ := sdk.NewImage("myapp").
		Domain("staging.example.com").
		Version("v1.0.0").
		Build()

	_, _ = plan.Audit("audit-app").
		Dockerfile("./app/Dockerfile").
		Source(stagingImage).
		RuleSet(sdk.RuleSetRecommended).
		Build()

	// Step 3: Scan for vulnerabilities
	_, _ = plan.Scan("scan-app").
		Source(stagingImage).
		Severity(sdk.SeverityHigh).
		Severity(sdk.SeverityCritical).
		Format(sdk.FormatJSON).
		Build()

	// Step 4: Sync to production if everything passes
	prodImage, _ := sdk.NewImage("myorg/myapp").
		Domain("ghcr.io").
		Version("v1.0.0").
		Build()

	_, _ = plan.Sync("promote-to-prod").
		Source(stagingImage).
		Destination(prodImage).
		Build()
	// Output:
}
