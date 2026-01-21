package policy_test

import (
	"context"
	"testing"

	"github.com/farcloser/quark/pkg/sys/policy"
)

// mockPolicy is a test helper that returns a fixed result.
type mockPolicy struct {
	name   string
	result policy.Result
}

func (m *mockPolicy) Name() string { return m.name }

func (m *mockPolicy) Evaluate(_ context.Context, _ any) policy.Result {
	return m.result
}

func newMockPolicy(name string, verdict policy.Verdict, message string) *mockPolicy {
	return &mockPolicy{
		name: name,
		result: policy.Result{
			Verdict: verdict,
			Policy:  name,
			Message: message,
		},
	}
}

// INTENTION: Result.String() should format verdict, policy, and message.
func TestResult_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		result   policy.Result
		expected string
	}{
		{
			name: "allow verdict",
			result: policy.Result{
				Verdict: policy.Allow,
				Policy:  "test-policy",
				Message: "looks good",
			},
			expected: "[allow] test-policy: looks good",
		},
		{
			name: "deny verdict",
			result: policy.Result{
				Verdict: policy.Deny,
				Policy:  "security-check",
				Message: "vulnerability found",
			},
			expected: "[deny] security-check: vulnerability found",
		},
		{
			name: "warn verdict",
			result: policy.Result{
				Verdict: policy.Warn,
				Policy:  "best-practices",
				Message: "deprecated API used",
			},
			expected: "[warn] best-practices: deprecated API used",
		},
		{
			name: "skip verdict",
			result: policy.Result{
				Verdict: policy.Skip,
				Policy:  "optional-check",
				Message: "not applicable",
			},
			expected: "[skip] optional-check: not applicable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.result.String()
			if got != tt.expected {
				t.Errorf("String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// INTENTION: Result.Allowed() should return true for Allow, Warn, Skip; false for Deny.
func TestResult_Allowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		verdict  policy.Verdict
		expected bool
	}{
		{policy.Allow, true},
		{policy.Warn, true},
		{policy.Skip, true},
		{policy.Deny, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.verdict), func(t *testing.T) {
			t.Parallel()

			result := policy.Result{Verdict: tt.verdict}
			if got := result.Allowed(); got != tt.expected {
				t.Errorf("Allowed() for %s = %v, want %v", tt.verdict, got, tt.expected)
			}
		})
	}
}
