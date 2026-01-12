package policy

import "context"

const (
	policyNameAll = "all"
	policyNameAny = "any"
)

// All requires all policies to allow (AND logic).
// Returns Deny on first denial, otherwise Allow.
// Warnings are collected but don't prevent progression.
func All(policies ...Policy) Policy {
	return &allPolicy{policies: policies}
}

type allPolicy struct {
	policies []Policy
}

func (*allPolicy) Name() string { return policyNameAll }

func (combinator *allPolicy) Evaluate(ctx context.Context, input any) Result {
	var warnings []Result

	for _, pol := range combinator.policies {
		result := pol.Evaluate(ctx, input)

		switch result.Verdict { //nolint:exhaustive // Skip and Allow have identical handling
		case Deny:
			return result // Fail fast
		case Warn:
			warnings = append(warnings, result)
		default:
			continue
		}
	}

	if len(warnings) > 0 {
		return Result{
			Verdict: Warn,
			Policy:  policyNameAll,
			Message: warnings[0].Message, // Surface first warning
			Meta: map[string]any{
				"warnings": len(warnings),
			},
		}
	}

	return Result{
		Verdict: Allow,
		Policy:  policyNameAll,
		Message: "all policies passed",
	}
}

// Any requires at least one policy to allow (OR logic).
// Returns Allow on first allow, otherwise the last denial.
func Any(policies ...Policy) Policy {
	return &anyPolicy{policies: policies}
}

type anyPolicy struct {
	policies []Policy
}

func (*anyPolicy) Name() string { return policyNameAny }

func (combinator *anyPolicy) Evaluate(ctx context.Context, input any) Result {
	var lastDeny Result

	for _, pol := range combinator.policies {
		result := pol.Evaluate(ctx, input)

		//nolint:exhaustive,revive // Skip is intentionally a no-op
		switch result.Verdict {
		case Allow, Warn:
			return result // Short circuit on first allow
		case Deny:
			lastDeny = result
		}
	}

	if lastDeny.Policy == "" {
		return Result{
			Verdict: Skip,
			Policy:  policyNameAny,
			Message: "no policies applied",
		}
	}

	return lastDeny
}
