package policy

import (
	"context"
	"fmt"
)

// Verdict represents the outcome of policy evaluation.
type Verdict string

const (
	// Allow indicates the policy allows the input.
	Allow Verdict = "allow"
	// Deny indicates the policy denies the input.
	Deny Verdict = "deny"
	// Warn indicates the policy allows the input but emits a warning.
	Warn Verdict = "warn"
	// Skip indicates the policy does not apply to this input.
	Skip Verdict = "skip"
)

// Result is returned by policy evaluation.
type Result struct {
	Verdict Verdict        // The evaluation outcome
	Policy  string         // Name of the policy that produced this result
	Message string         // Human-readable explanation
	Meta    map[string]any // Arbitrary metadata for audit logs
}

// String returns a human-readable representation of the result.
func (r Result) String() string {
	return fmt.Sprintf("[%s] %s: %s", r.Verdict, r.Policy, r.Message)
}

// Allowed returns true if the verdict allows progression.
func (r Result) Allowed() bool {
	return r.Verdict == Allow || r.Verdict == Warn || r.Verdict == Skip
}

// Policy evaluates an input and returns a result.
type Policy interface {
	// Name returns a unique identifier for this policy.
	Name() string

	// Evaluate inspects the input and returns a verdict.
	// The input type depends on the context (e.g., ImageInput for image checks).
	Evaluate(ctx context.Context, input any) Result
}
