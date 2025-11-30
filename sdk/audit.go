package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/audit"
)

// AuditRuleSet represents audit rule severity.
type AuditRuleSet struct {
	value string
}

//nolint:gochecknoglobals // AuditRuleSet enum pattern requires global variables
var (
	// RuleSetStrict represents strict audit rules.
	RuleSetStrict = AuditRuleSet{"strict"}
	// RuleSetRecommended represents recommended audit rules.
	RuleSetRecommended = AuditRuleSet{"recommended"}
	// RuleSetMinimal represents minimal audit rules.
	RuleSetMinimal = AuditRuleSet{"minimal"}
)

// String returns the string representation of the rule set.
func (r *AuditRuleSet) String() string {
	return r.value
}

// MarshalJSON implements json.Marshaler for AuditRuleSet.
func (r *AuditRuleSet) MarshalJSON() ([]byte, error) {
	//nolint:wrapcheck // Standard library JSON marshaling
	return json.Marshal(r.value)
}

// UnmarshalJSON implements json.Unmarshaler for AuditRuleSet.
func (r *AuditRuleSet) UnmarshalJSON(data []byte) error {
	var str string
	//nolint:wrapcheck // Standard library JSON unmarshaling
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	// Normalize to lowercase
	normalized := strings.ToLower(str)

	switch normalized {
	case "strict":
		r.value = "strict"
	case "recommended":
		r.value = "recommended"
	case "minimal":
		r.value = "minimal"
	default:
		return fmt.Errorf("%w: %q (valid: strict, recommended, minimal)", ErrInvalidAuditRuleSet, str)
	}

	return nil
}

// AuditArgs contains configuration options for creating an audit operation.
type AuditArgs struct {
	Description  string        // Required - operation name
	Dockerfile   string        // Optional - Dockerfile path (one of Dockerfile or Source required)
	Source       *Image        // Optional - image to audit
	RuleSet      AuditRuleSet  // Optional - rule set (default: strict)
	IgnoreChecks []string      // Optional - checks to ignore
	Timeout      time.Duration // Optional - operation timeout
}

// auditOp represents a Dockerfile and image quality audit.
type auditOp struct {
	opName       string
	dockerfile   string
	image        *Image
	registry     *Registry
	ruleSet      AuditRuleSet
	ignoreChecks []string
	timeout      time.Duration
	log          zerolog.Logger
}

func (a *auditOp) execute(ctx context.Context) error {
	// Apply timeout if configured
	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}

	var imageRef string

	if a.image != nil {
		imageRef = a.image.tagRef()
	}

	a.log.Info().
		Str("dockerfile", a.dockerfile).
		Str("image", imageRef).
		Str("ruleset", a.ruleSet.String()).
		Msg("auditing")

	auditor := audit.NewAuditor(a.log)
	allPassed := true

	// Audit Dockerfile if provided
	if a.dockerfile != "" {
		result, err := auditor.AuditDockerfile(ctx, a.dockerfile)
		if err != nil {
			return fmt.Errorf("failed to audit Dockerfile: %w", err)
		}

		if result.Passed {
			a.log.Info().Msg(result.Output)
		} else {
			a.log.Warn().Msg(result.Output)

			allPassed = false
		}
	}

	// Audit image if provided
	if a.image != nil {
		opts := audit.ImageAuditOptions{
			RuleSet:      a.ruleSet.String(),
			IgnoreChecks: a.ignoreChecks,
		}

		if a.registry != nil {
			opts.RegistryHost = a.registry.domain
			opts.Username = a.registry.username
			opts.Password = a.registry.token
		}

		result, err := auditor.AuditImage(ctx, imageRef, opts)
		if err != nil {
			return fmt.Errorf("failed to audit image: %w", err)
		}

		if result.Passed {
			a.log.Info().Msg(result.Output)
		} else {
			a.log.Warn().Msg(result.Output)

			allPassed = false
		}
	}

	if !allPassed {
		return ErrAuditFoundIssues
	}

	a.log.Info().Msg("audit passed")

	return nil
}

// operationName returns the audit operation name (implements operation interface).
func (a *auditOp) operationName() string {
	return a.opName
}
