// Package main demonstrates policy-based image validation with Quark.
//
// This example shows how to:
// - Apply built-in security policies to images
// - Combine multiple policies with AND/OR logic
// - Create custom policies for organization-specific rules
// - Chain policies with scan, audit, and sync actions
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/farcloser/quark/sdk"
	sdklog "github.com/farcloser/quark/sdk/logger"
	"github.com/farcloser/quark/sdk/policy"
	"github.com/farcloser/quark/sdk/scan"
)

func main() {
	ctx := context.Background()

	plan := sdk.NewPlan()

	// Configure registry
	ghcr := sdk.NewRegistry(sdk.RegistryOpts{
		Domain:   "ghcr.io",
		Username: os.Getenv("GHCR_USERNAME"),
		Token:    os.Getenv("GHCR_TOKEN"),
	})

	// Define image to validate
	image := ghcr.NewImage(sdk.ImageOpts{
		Name:    "myorg/myapp",
		Version: "v1.0.0",
	})

	// ============================================
	// EXAMPLE 1: Simple vulnerability policy
	// ============================================
	//
	// Scan the image and enforce vulnerability limits.
	// This fails the build if critical > 0 or high > 10.

	scannedImage := image.Scan(&scan.Options{})

	checkedImage := scannedImage.Check(
		policy.Scan{
			Critical: 0,
			High:     10,
			Medium:   policy.Ignore,
			Low:      policy.Ignore,
			Unknown:  policy.Ignore,
		},
	)

	// ============================================
	// EXAMPLE 2: Require signed images
	// ============================================
	//
	// Sync the image metadata (resolves digest, retrieves signature info).
	// Then use policies to enforce signature requirements.

	syncedImage := image.Sync()

	signedImage := syncedImage.Check(policy.RequireSignature())

	// ============================================
	// EXAMPLE 3: Require signature from specific source
	// ============================================
	//
	// For production environments, require images to be signed
	// by your CI/CD pipeline (GitHub Actions in this example).

	trustedImage := syncedImage.Check(policy.RequireSignatureFrom(
		"https://token.actions.githubusercontent.com",         // OIDC issuer
		`https://github.com/myorg/.*/.github/workflows/.*@.*`, // Subject regex pattern
	))

	// ============================================
	// EXAMPLE 4: Combined policies with AND logic
	// ============================================
	//
	// Use policy.All() to require ALL policies to pass.
	// The image must be signed AND have acceptable vulnerability counts.

	scannedAndSynced := image.Scan(&scan.Options{})

	// Chain sync after scan to have both results available
	scannedAndSynced = scannedAndSynced.Sync()

	strictImage := scannedAndSynced.Check(policy.All(
		policy.RequireSignature(),
		policy.Scan{
			Critical: 0,
			High:     5,
			Medium:   policy.Ignore,
			Low:      policy.Ignore,
			Unknown:  policy.Ignore,
		},
		policy.Audit{
			Fatal: 0,
			Warn:  10,
			Info:  policy.Ignore,
		},
	))

	// ============================================
	// EXAMPLE 5: Combined policies with OR logic
	// ============================================
	//
	// Use policy.Any() when ANY policy passing is acceptable.
	// Useful for gradual rollout or multiple valid configurations.

	flexibleImage := scannedAndSynced.Check(policy.Any(
		// Either: signed by our CI
		policy.RequireSignatureFrom(
			"https://token.actions.githubusercontent.com",
			`https://github.com/myorg/.*`,
		),
		// Or: no critical/high vulnerabilities
		policy.Scan{Critical: 0, High: 0, Medium: policy.Ignore, Low: policy.Ignore, Unknown: policy.Ignore},
	))

	// ============================================
	// EXAMPLE 6: Custom inline policy
	// ============================================
	//
	// Use policy.Func() for organization-specific rules
	// that aren't covered by built-in policies.

	customImage := scannedAndSynced.Check(policy.Func(
		"require-production-ready",
		func(_ context.Context, input *policy.ImageInput) policy.Result {
			// Require signature for production images
			if input.Signature == nil || !input.Signature.Signed {
				return policy.Result{
					Verdict: policy.Deny,
					Policy:  "require-production-ready",
					Message: "production images must be signed",
				}
			}

			// No critical vulnerabilities allowed
			if input.Scan != nil && input.Scan.Critical > 0 {
				return policy.Result{
					Verdict: policy.Deny,
					Policy:  "require-production-ready",
					Message: "production images cannot have critical vulnerabilities",
					Meta: map[string]any{
						"critical_count": input.Scan.Critical,
					},
				}
			}

			// Warn if there are many high vulnerabilities
			if input.Scan != nil && input.Scan.High > 20 {
				return policy.Result{
					Verdict: policy.Warn,
					Policy:  "require-production-ready",
					Message: "high vulnerability count exceeds recommended threshold",
					Meta: map[string]any{
						"high_count": input.Scan.High,
					},
				}
			}

			return policy.Result{
				Verdict: policy.Allow,
				Policy:  "require-production-ready",
				Message: "image meets production requirements",
			}
		},
	))

	// ============================================
	// EXAMPLE 7: Complete production pipeline
	// ============================================
	//
	// A realistic production pipeline that:
	// 1. Scans for vulnerabilities
	// 2. Syncs metadata (resolves digest, retrieves signature info)
	// 3. Enforces strict security policies
	// 4. Logs results

	productionImage := image.
		Scan(&scan.Options{}).
		Sync(). // Retrieves signature info automatically
		Check(policy.All(
			// Require signature from GitHub Actions workflow
			policy.RequireSignatureFrom(
				"https://token.actions.githubusercontent.com",
				`https://github.com/myorg/myapp/.github/workflows/release.yaml@refs/tags/.*`,
			),
			policy.Scan{
				Critical: 0,
				High:     5,
				Medium:   policy.Ignore,
				Low:      policy.Ignore,
				Unknown:  policy.Ignore,
			}, //nolint:mnd
		)).
		Log(&sdklog.Options{
			Format:     sdklog.FormatTable,
			ScanLevels: sdklog.ScanLevelsDefault,
		})

	// Add whichever example you want to run to the plan
	// Uncomment the one you want to test:
	plan.Add(checkedImage) // Example 1: Basic vulnerability check

	_ = signedImage     // Example 2: Require signature
	_ = trustedImage    // Example 3: Require signature from source
	_ = strictImage     // Example 4: AND combination
	_ = flexibleImage   // Example 5: OR combination
	_ = customImage     // Example 6: Custom policy
	_ = productionImage // Example 7: Full production pipeline

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		slog.Error("policy check failed", "error", err)
		os.Exit(1)
	}

	slog.Info("policy validation completed successfully")
}
