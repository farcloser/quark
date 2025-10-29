package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/audit"
)

// AuditRuleSet represents audit rule severity.
//
//nolint:recvcheck // MarshalJSON uses value receiver, UnmarshalJSON requires pointer receiver
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
func (r AuditRuleSet) String() string {
	return r.value
}

// MarshalJSON implements json.Marshaler for AuditRuleSet.
func (r AuditRuleSet) MarshalJSON() ([]byte, error) {
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

// Audit represents a Dockerfile and image quality audit.
type Audit struct {
	opName       string
	dockerfile   string
	image        *Image
	registry     *Registry
	ruleSet      AuditRuleSet
	ignoreChecks []string
	log          zerolog.Logger
}

// AuditBuilder builds an Audit.
type AuditBuilder struct {
	plan  *Plan
	audit *Audit
}

// Dockerfile sets the Dockerfile path to audit.
func (builder *AuditBuilder) Dockerfile(dockerfile string) *AuditBuilder {
	builder.audit.dockerfile = dockerfile

	return builder
}

// Source sets the image to audit.
// Registry credentials are looked up from the plan's registry collection using the image domain.
// If no registry is found, anonymous access will be used.
func (builder *AuditBuilder) Source(image *Image) *AuditBuilder {
	builder.audit.image = image
	builder.audit.registry = builder.plan.getRegistry(image.domain)

	return builder
}

// RuleSet sets the rule set severity.
func (builder *AuditBuilder) RuleSet(ruleSet AuditRuleSet) *AuditBuilder {
	builder.audit.ruleSet = ruleSet

	return builder
}

// IgnoreChecks sets specific Dockle checks to ignore (e.g., "DKL-DI-0005").
func (builder *AuditBuilder) IgnoreChecks(checks ...string) *AuditBuilder {
	builder.audit.ignoreChecks = append(builder.audit.ignoreChecks, checks...)

	return builder
}

// Build validates and adds the audit to the plan.
func (builder *AuditBuilder) Build() (*Audit, error) {
	if builder.audit.dockerfile == "" && builder.audit.image == nil {
		return nil, ErrAuditSourceRequired
	}

	if builder.audit.ruleSet == (AuditRuleSet{}) {
		builder.audit.ruleSet = RuleSetStrict
	}

	builder.plan.audits = append(builder.plan.audits, builder.audit)
	builder.plan.operations = append(builder.plan.operations, builder.audit)

	return builder.audit, nil
}

func (auditJob *Audit) execute(_ context.Context) error {
	var imageRef string

	if auditJob.image != nil {
		ref, err := auditJob.image.tagRef()
		if err != nil {
			return fmt.Errorf("failed to build image reference: %w", err)
		}

		imageRef = ref
	}

	auditJob.log.Info().
		Str("dockerfile", auditJob.dockerfile).
		Str("image", imageRef).
		Str("ruleset", auditJob.ruleSet.String()).
		Msg("auditing")

	auditor := audit.NewAuditor(auditJob.log)
	allPassed := true

	// Audit Dockerfile if provided
	if auditJob.dockerfile != "" {
		result, err := auditor.AuditDockerfile(auditJob.dockerfile)
		if err != nil {
			return fmt.Errorf("failed to audit Dockerfile: %w", err)
		}

		auditJob.log.Info().Msg(result.Output)

		if !result.Passed {
			allPassed = false
		}
	}

	// Audit image if provided
	if auditJob.image != nil {
		opts := audit.ImageAuditOptions{
			RuleSet:      auditJob.ruleSet.String(),
			IgnoreChecks: auditJob.ignoreChecks,
		}

		if auditJob.registry != nil {
			opts.RegistryHost = auditJob.registry.host
			opts.Username = auditJob.registry.username
			opts.Password = auditJob.registry.password
		}

		result, err := auditor.AuditImage(imageRef, opts)
		if err != nil {
			return fmt.Errorf("failed to audit image: %w", err)
		}

		auditJob.log.Info().Msg(result.Output)

		if !result.Passed {
			allPassed = false
		}
	}

	if !allPassed {
		auditJob.log.Warn().Msg("audit found issues")

		return ErrAuditFoundIssues
	}

	auditJob.log.Info().Msg("audit passed")

	return nil
}

// operationName returns the audit operation name (implements operation interface).
func (auditJob *Audit) operationName() string {
	return auditJob.opName
}
