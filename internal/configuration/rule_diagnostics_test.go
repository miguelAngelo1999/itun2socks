package configuration

import "testing"

func TestSubsumesIdenticalCriteria(t *testing.T) {
	earlier := RuleItem{
		Conditions: []RuleCondition{{Type: "DOMAIN", Value: "unleash.codeium.com"}},
		Policy:     RulePolicy{Kind: PolicyKindReject},
	}
	later := RuleItem{
		Conditions: []RuleCondition{{Type: "DOMAIN", Value: "unleash.codeium.com"}},
		Policy:     RulePolicy{Kind: PolicyKindSelected},
	}
	if _, ok := subsumes(earlier, later); !ok {
		t.Error("identical criteria with different policies should shadow")
	}
}

func TestSubsumesDomainSuffixOverSpecificDomain(t *testing.T) {
	earlier := RuleItem{
		Conditions: []RuleCondition{{Type: "DOMAIN-SUFFIX", Value: "example.com"}},
		Policy:     RulePolicy{Kind: PolicyKindDirect},
	}
	later := RuleItem{
		Conditions: []RuleCondition{{Type: "DOMAIN", Value: "api.example.com"}},
		Policy:     RulePolicy{Kind: PolicyKindSelected},
	}
	if _, ok := subsumes(earlier, later); !ok {
		t.Error("a domain suffix should shadow a more specific domain below it")
	}
}

func TestSamePolicyIsNotShadowing(t *testing.T) {
	a := RuleItem{
		Conditions: []RuleCondition{{Type: "DOMAIN-SUFFIX", Value: "example.com"}},
		Policy:     RulePolicy{Kind: PolicyKindDirect},
	}
	b := RuleItem{
		Conditions: []RuleCondition{{Type: "DOMAIN", Value: "api.example.com"}},
		Policy:     RulePolicy{Kind: PolicyKindDirect},
	}
	if !samePolicy(a, b) {
		t.Fatal("policies should compare equal")
	}
}

// A protocol-scoped rule is skipped for the other transport, so it cannot make
// an unscoped rule unreachable.
func TestProtocolScopedRuleDoesNotShadowUnscoped(t *testing.T) {
	earlier := RuleItem{
		Conditions: []RuleCondition{{Type: "DOMAIN", Value: "example.com"}},
		Policy:     RulePolicy{Kind: PolicyKindReject},
		Network:    "tcp",
	}
	later := RuleItem{
		Conditions: []RuleCondition{{Type: "DOMAIN", Value: "example.com"}},
		Policy:     RulePolicy{Kind: PolicyKindDirect},
	}
	if _, ok := subsumes(earlier, later); ok {
		t.Error("a tcp-only rule must not shadow a rule that also covers udp")
	}
}

// A compound rule is narrower than any single condition, so it is not treated
// as shadowing.
func TestCompoundRuleDoesNotShadow(t *testing.T) {
	earlier := RuleItem{
		Conditions: []RuleCondition{
			{Type: "DOMAIN-SUFFIX", Value: "example.com"},
			{Type: "DST-PORT", Value: "443"},
		},
		Policy: RulePolicy{Kind: PolicyKindReject},
	}
	later := RuleItem{
		Conditions: []RuleCondition{{Type: "DOMAIN", Value: "api.example.com"}},
		Policy:     RulePolicy{Kind: PolicyKindDirect},
	}
	if _, ok := subsumes(earlier, later); ok {
		t.Error("a compound rule must not be reported as shadowing")
	}
}

func TestUnrelatedDomainsDoNotShadow(t *testing.T) {
	earlier := RuleItem{
		Conditions: []RuleCondition{{Type: "DOMAIN-SUFFIX", Value: "example.com"}},
		Policy:     RulePolicy{Kind: PolicyKindReject},
	}
	later := RuleItem{
		Conditions: []RuleCondition{{Type: "DOMAIN", Value: "notexample.org"}},
		Policy:     RulePolicy{Kind: PolicyKindDirect},
	}
	if _, ok := subsumes(earlier, later); ok {
		t.Error("unrelated domains must not be reported as shadowing")
	}
}

// The live config carries a REJECT and a PROXY rule for the same host. The
// PROXY rule has never matched anything.
func TestLiveConfigFindsTheCodeiumShadow(t *testing.T) {
	c := loadFixture(t)
	migrated, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}

	effective := effectiveFrom(migrated)
	found := false
	for i := range effective {
		for j := 0; j < i; j++ {
			if samePolicy(effective[j], effective[i]) {
				continue
			}
			if _, ok := subsumes(effective[j], effective[i]); ok {
				t.Logf("shadowed: %s by %s", effective[i].Slug, effective[j].Slug)
				found = true
			}
		}
	}
	if !found {
		t.Error("expected at least one shadowed rule in the live config")
	}
}
