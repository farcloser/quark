// Package main demonstrates auditing Dockerfiles and container images.
package main

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/sdk"
)

func main() {
	ctx := context.Background()
	sdk.ConfigureDefaultLogger(ctx)

	plan := sdk.NewPlan("audit-example")

	// Define image to audit
	exampleImage := sdk.NewImage("alpine").
		Domain("docker.io").
		Version("3.19").
		Build()

	// Audit image against strict ruleset
	// Note: Dockerfile audit requires local Dockerfile path
	plan.Audit("alpine-audit").
		Source(exampleImage).
		RuleSet(sdk.RuleSetStrict).
		IgnoreChecks("CIS-DI-0001").
		Build()

	// Execute plan
	if err := plan.Execute(ctx); err != nil {
		log.Fatal().Err(err).Msg("audit failed")
	}

	log.Info().Msg("audit completed successfully")
}
