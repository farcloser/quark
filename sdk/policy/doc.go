// Package policy provides policy types and built-in policies for quark operations.
//
// Policies evaluate inputs and return verdicts (allow, deny, warn, skip).
// They can be composed using All() and Any() combinators.
//
// Example usage:
//
//	// Built-in policies
//	scanned := img.Scan(scanOpts)
//	checked := scanned.Check(policy.MaxVulnerabilities(0, 10))
//	copied := checked.CopyTo(dest, syncOpts)
//
//	// Custom policies
//	checked := scanned.Check(policy.Func("custom", func(ctx context.Context, input *policy.ImageInput) policy.Result {
//	    if input.Scan != nil && input.Scan.Critical > 0 {
//	        return policy.Result{Verdict: policy.Deny, Message: "no critical vulns allowed"}
//	    }
//	    return policy.Result{Verdict: policy.Allow}
//	}))
//
//	// Composed policies
//	checked := scanned.Check(policy.All(
//	    policy.RequireSignature(),
//	    policy.MaxVulnerabilities(0, 5),
//	))
package policy
