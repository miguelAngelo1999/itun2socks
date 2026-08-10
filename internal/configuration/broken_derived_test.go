package configuration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeTempConfig points the package at a scratch config file holding cfg.
func writeTempConfig(t *testing.T, cfg Config) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	prev := configFilePath.Load()
	configFilePath.Store(path)
	t.Cleanup(func() { configFilePath.Store(prev) })
}

func proxyEntry(id, name string) map[string]any {
	return map[string]any{"id": id, "name": name, "type": "http",
		"server": "example.com", "port": 8080}
}

// Broken is computed state, so a value on disk must never be trusted.
//
// It was only recomputed when rules were mutated. effectiveFrom skips broken
// rules, so a rule flagged once was excluded from evaluation permanently, even
// after its proxy was present again. Three live rules pointing at an existing
// proxy were dead this way: the flag was written during migration, before the
// proxy id resolved, and nothing revisited it. Their traffic quietly fell through
// to the default policy.
func TestReadClearsStaleBrokenWhenProxyExists(t *testing.T) {
	writeTempConfig(t, Config{
		Proxy: []map[string]any{proxyEntry("proxy-lp", "LP")},
		RuleGroups: []RuleGroup{
			{Id: "g1", Name: "Work", Enabled: true, Order: 0},
		},
		CustomizedRules: []RuleItem{{
			Id:   "r1",
			Slug: "domain-intranet-lp",
			Conditions: []RuleCondition{
				{Type: "DOMAIN", Value: "intranet.example.com"},
			},
			Policy:  RulePolicy{Kind: PolicyKindProxy, ProxyId: "proxy-lp"},
			Enabled: true,
			// Stale: the proxy is right there in the list above.
			Broken: `proxy "proxy-lp" no longer exists`,
		}},
	})

	c, err := Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := c.CustomizedRules[0].Broken; got != "" {
		t.Fatalf("Broken = %q, want empty: the proxy exists so the flag is stale", got)
	}

	// The point of clearing it: the rule has to reach the engine.
	eff := effectiveFrom(c)
	if len(eff) != 1 || eff[0].Id != "r1" {
		t.Fatalf("effective rules = %+v, want r1 to be evaluated", eff)
	}
	if got := eff[0].PolicyValue(); string(got) != "proxy-lp" {
		t.Fatalf("policy = %q, want the proxy id so traffic routes to LP", got)
	}
}

// The flag must still be set when the proxy really is gone, so such a rule is
// excluded rather than quietly falling back to another policy.
func TestReadMarksBrokenWhenProxyMissing(t *testing.T) {
	writeTempConfig(t, Config{
		Proxy: []map[string]any{proxyEntry("proxy-lp", "LP")},
		RuleGroups: []RuleGroup{
			{Id: "g1", Name: "Work", Enabled: true, Order: 0},
		},
		CustomizedRules: []RuleItem{{
			Id:   "r1",
			Slug: "domain-old-proxy",
			Conditions: []RuleCondition{
				{Type: "DOMAIN", Value: "old.example.com"},
			},
			Policy:  RulePolicy{Kind: PolicyKindProxy, ProxyId: "Proxy"},
			Enabled: true,
			// Absent on disk; Read must derive it.
			Broken: "",
		}},
	})

	c, err := Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if c.CustomizedRules[0].Broken == "" {
		t.Fatal("Broken is empty, but the targeted proxy does not exist")
	}
	if eff := effectiveFrom(c); len(eff) != 0 {
		t.Fatalf("effective rules = %+v, want none: a broken rule must not be evaluated", eff)
	}
}

// A rule that does not target a named proxy can never be broken by this rule.
func TestReadClearsBrokenOnNonProxyPolicies(t *testing.T) {
	writeTempConfig(t, Config{
		Proxy: []map[string]any{proxyEntry("proxy-lp", "LP")},
		RuleGroups: []RuleGroup{
			{Id: "g1", Name: "Blocked", Enabled: true, Order: 0},
		},
		CustomizedRules: []RuleItem{{
			Id:         "r1",
			Slug:       "domain-ads-reject",
			Conditions: []RuleCondition{{Type: "DOMAIN", Value: "ads.example.com"}},
			Policy:     RulePolicy{Kind: PolicyKindReject},
			Enabled:    true,
			Broken:     "left over from something else",
		}},
	})

	c, err := Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := c.CustomizedRules[0].Broken; got != "" {
		t.Fatalf("Broken = %q, want empty for a REJECT policy", got)
	}
}
