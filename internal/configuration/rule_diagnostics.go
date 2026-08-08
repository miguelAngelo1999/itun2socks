package configuration

// Rule diagnostics.
//
// Ordered first-match evaluation means a broad rule placed above a narrow one
// makes the narrow one unreachable. Every comparable tool has this property and
// none detects it, leaving users to infer it from logs. Because rules now have
// stable ids, the shadowing relation can be reported directly.

import "strings"

// Shadow reports a rule that can never match because an earlier rule with a
// different policy already covers everything it would.
type Shadow struct {
	RuleId       string `json:"ruleId"`
	RuleSlug     string `json:"ruleSlug"`
	ShadowedById string `json:"shadowedById"`
	ShadowedBy   string `json:"shadowedBySlug"`
	Reason       string `json:"reason"`
}

// BrokenRule reports a rule that cannot be applied, most often one targeting a
// proxy that has been deleted.
type BrokenRule struct {
	RuleId   string `json:"ruleId"`
	RuleSlug string `json:"ruleSlug"`
	Reason   string `json:"reason"`
}

// ShadowedRules finds unreachable rules in the effective sequence.
//
// Only rules that would actually be evaluated are considered: a disabled rule is
// not shadowed, it is simply off.
func ShadowedRules() ([]Shadow, error) {
	effective, err := EffectiveRules()
	if err != nil {
		return nil, err
	}

	out := make([]Shadow, 0)
	for i := range effective {
		later := effective[i]
		for j := 0; j < i; j++ {
			earlier := effective[j]
			// Same outcome means order is irrelevant.
			if samePolicy(earlier, later) {
				continue
			}
			if reason, shadows := subsumes(earlier, later); shadows {
				out = append(out, Shadow{
					RuleId:       later.Id,
					RuleSlug:     later.Slug,
					ShadowedById: earlier.Id,
					ShadowedBy:   earlier.Slug,
					Reason:       reason,
				})
				break
			}
		}
	}
	return out, nil
}

func BrokenRules() ([]BrokenRule, error) {
	rules, err := GetRules()
	if err != nil {
		return nil, err
	}
	out := make([]BrokenRule, 0)
	for _, r := range rules {
		if r.Broken == "" {
			continue
		}
		out = append(out, BrokenRule{RuleId: r.Id, RuleSlug: r.Slug, Reason: r.Broken})
	}
	return out, nil
}

func samePolicy(a, b RuleItem) bool {
	return a.Policy.Kind == b.Policy.Kind && a.Policy.ProxyId == b.Policy.ProxyId
}

// subsumes reports whether earlier makes later unreachable.
//
// Deliberately conservative. A false positive trains users to ignore the
// warning, so only relations that are certainly shadowing are reported:
// identical criteria, or a domain suffix covering a more specific domain.
// Set-theoretic CIDR containment and regex subsumption are not attempted.
func subsumes(earlier, later RuleItem) (string, bool) {
	// A protocol-scoped earlier rule cannot shadow a rule that applies to
	// everything, since it is skipped for the other transport.
	if earlier.Network != "" && earlier.Network != later.Network {
		return "", false
	}

	// Multi-condition rules are narrower than any single condition, so an
	// earlier compound rule is not treated as shadowing.
	if len(earlier.Conditions) != 1 || len(later.Conditions) != 1 {
		return "", false
	}

	e := earlier.Conditions[0]
	l := later.Conditions[0]

	et := strings.ToUpper(e.Type)
	lt := strings.ToUpper(l.Type)
	ev := strings.ToLower(e.Value)
	lv := strings.ToLower(l.Value)

	if et == lt && ev == lv {
		return "identical criteria with a different policy", true
	}

	if et == "DOMAIN-SUFFIX" {
		switch lt {
		case "DOMAIN", "DOMAIN-SUFFIX":
			if lv == ev || strings.HasSuffix(lv, "."+ev) {
				return "covered by the earlier domain suffix", true
			}
		}
	}

	if et == "DOMAIN-KEYWORD" && (lt == "DOMAIN" || lt == "DOMAIN-SUFFIX") {
		if strings.Contains(lv, ev) {
			return "covered by the earlier domain keyword", true
		}
	}

	return "", false
}
