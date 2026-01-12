package sdk

import (
	"context"
	"fmt"
	"log/slog"

	devpolicy "github.com/farcloser/quark/dev/policy"
	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/analyze/dockerfile"
	"github.com/farcloser/quark/sdk/policy"
)

type builderCheckAction struct {
	*resource.BaseAction

	policy policy.Policy
	input  *Builder
	output *Builder
}

func (ca *builderCheckAction) AddOutput(
	name string,
	out resource.Resource,
	copyFrom ...resource.Resource,
) resource.Resource {
	return resource.RegisterOutput(ca, ca.BaseAction, name, out, copyFrom...)
}

func (ca *builderCheckAction) Execute(ctx context.Context) error {
	// Build policy input from the output builder state
	// (which has been populated via Bootstrap from the input)
	policyInput := ca.buildPolicyInput()

	result := ca.policy.Evaluate(ctx, policyInput)

	switch result.Verdict {
	case devpolicy.Allow:
		ca.output.log.InfoContext(ctx, "policy check passed",
			slog.String(logKeyPolicy, result.Policy),
			slog.String(logKeyMessage, result.Message),
		)

		return nil

	case devpolicy.Warn:
		ca.output.log.WarnContext(ctx, "policy check warning",
			slog.String(logKeyPolicy, result.Policy),
			slog.String(logKeyMessage, result.Message),
		)

		return nil

	case devpolicy.Skip:
		ca.output.log.DebugContext(ctx, "policy check skipped",
			slog.String(logKeyPolicy, result.Policy),
			slog.String(logKeyMessage, result.Message),
		)

		return nil

	case devpolicy.Deny:
		ca.output.log.ErrorContext(ctx, "policy check failed",
			slog.String(logKeyPolicy, result.Policy),
			slog.String(logKeyMessage, result.Message),
		)

		return fmt.Errorf("%w: %s - %s", policy.ErrCheckFailed, result.Policy, result.Message)

	default:
		return fmt.Errorf("%w: unknown verdict %q from policy %s",
			policy.ErrCheckFailed, result.Verdict, result.Policy)
	}
}

// buildPolicyInput constructs the policy input from the current builder state.
func (ca *builderCheckAction) buildPolicyInput() *policy.BuilderInput {
	builder := ca.output

	policyInput := &policy.BuilderInput{
		Dockerfile: builder.options.Dockerfile,
		Context:    builder.options.Context,
	}

	// Populate lint results if available
	if builder.lintResult != nil {
		policyInput.Lint = buildLintInput(builder.lintResult)
	}

	return policyInput
}

// buildLintInput constructs LintInput from godolint results.
func buildLintInput(result *dockerfile.Result) *policy.LintInput {
	lintInput := &policy.LintInput{}

	for _, violation := range result.Violations {
		switch violation.Severity {
		case dockerfile.SeverityError:
			lintInput.Error++
		case dockerfile.SeverityWarning:
			lintInput.Warning++
		case dockerfile.SeverityInfo:
			lintInput.Info++
		case dockerfile.SeverityStyle:
			lintInput.Style++
		}
	}

	return lintInput
}
