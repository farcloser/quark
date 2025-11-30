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
	amd64Node, err := sdk.NewBuildNode(&sdk.BuildNodeOpts{
		Name:     "amd64-builder",
		Endpoint: "user@amd64-builder.example.com",
		Platform: sdk.PlatformAMD64,
	})
	if err != nil {
		log.Fatal(err)
	}

	plan.AddBuildNode(amd64Node)

	arm64Node, err := sdk.NewBuildNode(&sdk.BuildNodeOpts{
		Name:     "arm64-builder",
		Endpoint: "user@arm64-builder.example.com",
		Platform: sdk.PlatformARM64,
	})
	if err != nil {
		log.Fatal(err)
	}

	plan.AddBuildNode(arm64Node)

	// Build multi-platform image
	_, err = plan.Build(&sdk.BuildArgs{
		Name:       "my-app",
		Context:    "./app",
		Dockerfile: "Dockerfile",
		Tag:        "ghcr.io/myorg/myapp:v1.0.0",
		Nodes:      []*sdk.BuildNode{amd64Node, arm64Node},
	})
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
	plan.AddRegistry(sdk.NewRegistry(&sdk.RegistryOpts{
		Domain:   "docker.io",
		Username: "sourceuser",
		Token:    "sourcepass",
	}))

	// Configure destination registry (GitHub Container Registry)
	plan.AddRegistry(sdk.NewRegistry(&sdk.RegistryOpts{
		Domain:   "ghcr.io",
		Username: "destuser",
		Token:    "destpass",
	}))

	// Create source image reference with digest (required for security)
	sourceImage, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "library/alpine",
		Version: "3.20",
		Digest:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create destination image reference
	destImage, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "myorg/alpine",
		Domain:  "ghcr.io",
		Version: "3.20",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Sync the image
	_, err = plan.Sync(&sdk.SyncArgs{
		Description: "alpine-sync",
		Source:      sourceImage,
		Destination: destImage,
	})
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
	plan.AddRegistry(sdk.NewRegistry(&sdk.RegistryOpts{
		Domain:   "ghcr.io",
		Username: "user",
		Token:    "pass",
	}))

	// Create image reference with digest
	image, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "myorg/myapp",
		Domain:  "ghcr.io",
		Version: "v1.0.0",
		Digest:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Scan for HIGH and CRITICAL vulnerabilities
	_, err = plan.Scan(&sdk.ScanArgs{
		Description: "security-scan",
		Source:      image,
		SeverityChecks: []sdk.ScanSeverityCheck{
			{Threshold: sdk.SeverityHigh, Action: sdk.ActionError},
			{Threshold: sdk.SeverityCritical, Action: sdk.ActionError},
		},
		Format: sdk.FormatTable,
	})
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
	plan.AddRegistry(sdk.NewRegistry(&sdk.RegistryOpts{
		Domain:   "ghcr.io",
		Username: "user",
		Token:    "pass",
	}))

	// Create image reference
	image, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "myorg/myapp",
		Domain:  "ghcr.io",
		Version: "v1.0.0",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Audit Dockerfile and image with strict rules
	_, err = plan.Audit(&sdk.AuditArgs{
		Description:  "security-audit",
		Dockerfile:   "./Dockerfile",
		Source:       image,
		RuleSet:      sdk.RuleSetStrict,
		IgnoreChecks: []string{"DKL-DI-0005"},
	})
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
	plan.AddRegistry(sdk.NewRegistry(&sdk.RegistryOpts{
		Domain:   "docker.io",
		Username: "user",
		Token:    "pass",
	}))

	// Create image reference with current digest
	image, err := sdk.NewImage(&sdk.ImageOpts{
		Name:    "library/alpine",
		Version: "3.20",
		Digest:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Check if tag points to a different digest (version update available)
	_, err = plan.CheckVersion("alpine-version-check", image, false)
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
	plan.AddRegistry(sdk.NewRegistry(&sdk.RegistryOpts{
		Domain:   "staging.example.com",
		Username: "stg-user",
		Token:    "stg-pass",
	}))

	plan.AddRegistry(sdk.NewRegistry(&sdk.RegistryOpts{
		Domain:   "ghcr.io",
		Username: "prod-user",
		Token:    "prod-pass",
	}))

	// Configure build nodes
	amd64Node, _ := sdk.NewBuildNode(&sdk.BuildNodeOpts{
		Name:     "amd64-builder",
		Endpoint: "user@builder.example.com",
		Platform: sdk.PlatformAMD64,
	})

	plan.AddBuildNode(amd64Node)

	arm64Node, _ := sdk.NewBuildNode(&sdk.BuildNodeOpts{
		Name:     "arm64-builder",
		Endpoint: "user@arm-builder.example.com",
		Platform: sdk.PlatformARM64,
	})

	plan.AddBuildNode(arm64Node)

	// Step 1: Build image
	_, _ = plan.Build(&sdk.BuildArgs{
		Name:       "build-app",
		Context:    "./app",
		Dockerfile: "Dockerfile",
		Tag:        "staging.example.com/myapp:v1.0.0",
		Nodes:      []*sdk.BuildNode{amd64Node, arm64Node},
	})

	// Step 2: Audit Dockerfile and built image
	stagingImage, _ := sdk.NewImage(&sdk.ImageOpts{
		Name:    "myapp",
		Domain:  "staging.example.com",
		Version: "v1.0.0",
	})

	_, _ = plan.Audit(&sdk.AuditArgs{
		Description: "audit-app",
		Dockerfile:  "./app/Dockerfile",
		Source:      stagingImage,
		RuleSet:     sdk.RuleSetRecommended,
	})

	// Step 3: Scan for vulnerabilities
	_, _ = plan.Scan(&sdk.ScanArgs{
		Description: "scan-app",
		Source:      stagingImage,
		SeverityChecks: []sdk.ScanSeverityCheck{
			{Threshold: sdk.SeverityHigh, Action: sdk.ActionError},
			{Threshold: sdk.SeverityCritical, Action: sdk.ActionError},
		},
		Format: sdk.FormatJSON,
	})

	// Step 4: Sync to production if everything passes
	prodImage, _ := sdk.NewImage(&sdk.ImageOpts{
		Name:    "myorg/myapp",
		Domain:  "ghcr.io",
		Version: "v1.0.0",
	})

	_, _ = plan.Sync(&sdk.SyncArgs{
		Description: "promote-to-prod",
		Source:      stagingImage,
		Destination: prodImage,
	})
	// Output:
}
