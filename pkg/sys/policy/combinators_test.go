package policy_test

import (
	"context"
	"testing"

	"github.com/farcloser/quark/pkg/sys/policy"
)

// INTENTION: All combinator should require all policies to allow (AND logic).
func TestAll(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name            string
		policies        []policy.Policy
		expectedVerdict policy.Verdict
		expectedAllowed bool
	}{
		{
			name:            "no policies returns allow",
			policies:        []policy.Policy{},
			expectedVerdict: policy.Allow,
			expectedAllowed: true,
		},
		{
			name: "single allow returns allow",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Allow, "ok"),
			},
			expectedVerdict: policy.Allow,
			expectedAllowed: true,
		},
		{
			name: "single deny returns deny",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Deny, "failed"),
			},
			expectedVerdict: policy.Deny,
			expectedAllowed: false,
		},
		{
			name: "all allow returns allow",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Allow, "ok1"),
				newMockPolicy("p2", policy.Allow, "ok2"),
				newMockPolicy("p3", policy.Allow, "ok3"),
			},
			expectedVerdict: policy.Allow,
			expectedAllowed: true,
		},
		{
			name: "one deny among allows returns deny",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Allow, "ok"),
				newMockPolicy("p2", policy.Deny, "failed"),
				newMockPolicy("p3", policy.Allow, "ok"),
			},
			expectedVerdict: policy.Deny,
			expectedAllowed: false,
		},
		{
			name: "deny short-circuits evaluation",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Deny, "first fails"),
				newMockPolicy("p2", policy.Allow, "never reached"),
			},
			expectedVerdict: policy.Deny,
			expectedAllowed: false,
		},
		{
			name: "single warn returns warn",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Warn, "caution"),
			},
			expectedVerdict: policy.Warn,
			expectedAllowed: true,
		},
		{
			name: "warnings collected but allow progression",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Allow, "ok"),
				newMockPolicy("p2", policy.Warn, "warning1"),
				newMockPolicy("p3", policy.Warn, "warning2"),
			},
			expectedVerdict: policy.Warn,
			expectedAllowed: true,
		},
		{
			name: "skip is treated as allow",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Skip, "not applicable"),
				newMockPolicy("p2", policy.Allow, "ok"),
			},
			expectedVerdict: policy.Allow,
			expectedAllowed: true,
		},
		{
			name: "all skip returns allow",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Skip, "n/a"),
				newMockPolicy("p2", policy.Skip, "n/a"),
			},
			expectedVerdict: policy.Allow,
			expectedAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			combined := policy.All(tt.policies...)
			result := combined.Evaluate(ctx, nil)

			if result.Verdict != tt.expectedVerdict {
				t.Errorf("Verdict = %s, want %s", result.Verdict, tt.expectedVerdict)
			}

			if result.Allowed() != tt.expectedAllowed {
				t.Errorf("Allowed() = %v, want %v", result.Allowed(), tt.expectedAllowed)
			}
		})
	}
}

// INTENTION: All combinator should have name "all".
func TestAll_Name(t *testing.T) {
	t.Parallel()

	combined := policy.All()
	if got := combined.Name(); got != "all" {
		t.Errorf("Name() = %q, want %q", got, "all")
	}
}

// INTENTION: Any combinator should require at least one policy to allow (OR logic).
func TestAny(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name            string
		policies        []policy.Policy
		expectedVerdict policy.Verdict
		expectedAllowed bool
	}{
		{
			name:            "no policies returns skip",
			policies:        []policy.Policy{},
			expectedVerdict: policy.Skip,
			expectedAllowed: true,
		},
		{
			name: "single allow returns allow",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Allow, "ok"),
			},
			expectedVerdict: policy.Allow,
			expectedAllowed: true,
		},
		{
			name: "single deny returns deny",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Deny, "failed"),
			},
			expectedVerdict: policy.Deny,
			expectedAllowed: false,
		},
		{
			name: "one allow among denies returns allow",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Deny, "fail1"),
				newMockPolicy("p2", policy.Allow, "ok"),
				newMockPolicy("p3", policy.Deny, "fail3"),
			},
			expectedVerdict: policy.Allow,
			expectedAllowed: true,
		},
		{
			name: "allow short-circuits evaluation",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Allow, "first passes"),
				newMockPolicy("p2", policy.Deny, "never reached"),
			},
			expectedVerdict: policy.Allow,
			expectedAllowed: true,
		},
		{
			name: "all deny returns last deny",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Deny, "fail1"),
				newMockPolicy("p2", policy.Deny, "fail2"),
				newMockPolicy("p3", policy.Deny, "fail3"),
			},
			expectedVerdict: policy.Deny,
			expectedAllowed: false,
		},
		{
			name: "warn counts as allow",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Deny, "fail"),
				newMockPolicy("p2", policy.Warn, "caution"),
			},
			expectedVerdict: policy.Warn,
			expectedAllowed: true,
		},
		{
			name: "all skip returns skip",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Skip, "n/a"),
				newMockPolicy("p2", policy.Skip, "n/a"),
			},
			expectedVerdict: policy.Skip,
			expectedAllowed: true,
		},
		{
			name: "skip does not count as allow for short-circuit",
			policies: []policy.Policy{
				newMockPolicy("p1", policy.Skip, "n/a"),
				newMockPolicy("p2", policy.Deny, "fail"),
			},
			expectedVerdict: policy.Deny,
			expectedAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			combined := policy.Any(tt.policies...)
			result := combined.Evaluate(ctx, nil)

			if result.Verdict != tt.expectedVerdict {
				t.Errorf("Verdict = %s, want %s", result.Verdict, tt.expectedVerdict)
			}

			if result.Allowed() != tt.expectedAllowed {
				t.Errorf("Allowed() = %v, want %v", result.Allowed(), tt.expectedAllowed)
			}
		})
	}
}

// INTENTION: Any combinator should have name "any".
func TestAny_Name(t *testing.T) {
	t.Parallel()

	combined := policy.Any()
	if got := combined.Name(); got != "any" {
		t.Errorf("Name() = %q, want %q", got, "any")
	}
}

// INTENTION: Combinators should preserve policy name from denying policy.
func TestAll_PreservesDenyingPolicyName(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	combined := policy.All(
		newMockPolicy("policy-a", policy.Allow, "ok"),
		newMockPolicy("policy-b", policy.Deny, "blocked"),
		newMockPolicy("policy-c", policy.Allow, "ok"),
	)

	result := combined.Evaluate(ctx, nil)

	if result.Policy != "policy-b" {
		t.Errorf("Policy = %q, want %q", result.Policy, "policy-b")
	}

	if result.Message != "blocked" {
		t.Errorf("Message = %q, want %q", result.Message, "blocked")
	}
}

// INTENTION: Any combinator should preserve policy name from allowing policy.
func TestAny_PreservesAllowingPolicyName(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	combined := policy.Any(
		newMockPolicy("policy-a", policy.Deny, "fail"),
		newMockPolicy("policy-b", policy.Allow, "passed"),
		newMockPolicy("policy-c", policy.Deny, "fail"),
	)

	result := combined.Evaluate(ctx, nil)

	if result.Policy != "policy-b" {
		t.Errorf("Policy = %q, want %q", result.Policy, "policy-b")
	}

	if result.Message != "passed" {
		t.Errorf("Message = %q, want %q", result.Message, "passed")
	}
}
