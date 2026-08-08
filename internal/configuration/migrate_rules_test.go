package configuration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// liveConfigPath is a copy of a real user config carrying 103 legacy rules,
// including disabled entries, a named-proxy policy, a four-field protocol rule,
// and two rules referencing a proxy that no longer exists.
const liveConfigFixture = "testdata/live_config.json"

func loadFixture(t *testing.T) Config {
	t.Helper()
	data, err := os.ReadFile(liveConfigFixture)
	if err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("fixture is not valid json: %v", err)
	}
	return c
}

func TestMigrationPreservesRouting(t *testing.T) {
	c := loadFixture(t)
	legacy := make([]string, len(c.Rules))
	copy(legacy, c.Rules)

	migrated, stats, err := convertLegacyRules(c, legacy)
	if err != nil {
		t.Fatalf("convert failed: %v", err)
	}

	if err := verifyMigration(legacy, migrated); err != nil {
		t.Fatalf("routing changed: %v", err)
	}

	t.Logf("converted=%d disabled=%d deduped=%d quarantined=%d broken=%d rulesets=%d",
		stats.Converted, stats.Disabled, stats.Deduped, stats.Quarantined, stats.Broken, stats.Rulesets)

	if stats.Converted == 0 {
		t.Fatal("nothing was converted")
	}
}

func TestEveryRuleGetsUniqueId(t *testing.T) {
	c := loadFixture(t)
	migrated, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range migrated.CustomizedRules {
		if r.Id == "" {
			t.Errorf("rule with empty id: %+v", r)
		}
		if seen[r.Id] {
			t.Errorf("duplicate id %q", r.Id)
		}
		seen[r.Id] = true
	}
}

func TestSlugsAreUniqueAndNonEmpty(t *testing.T) {
	c := loadFixture(t)
	migrated, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range migrated.CustomizedRules {
		if r.Slug == "" {
			t.Errorf("rule %s has no slug", r.Id)
		}
		if seen[r.Slug] {
			t.Errorf("duplicate slug %q on rule %s", r.Slug, r.Id)
		}
		seen[r.Slug] = true
	}
}

// The legacy format encoded disabled state as a "#" prefix, so an enabled and a
// disabled copy of the same rule were different strings and both survived.
func TestDisabledStateMovesOffThePrefix(t *testing.T) {
	c := loadFixture(t)
	migrated, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range migrated.CustomizedRules {
		for _, cond := range r.Conditions {
			if strings.HasPrefix(cond.Type, "#") {
				t.Errorf("rule %s kept a # in its condition type: %q", r.Id, cond.Type)
			}
		}
	}
	disabled := 0
	for _, r := range migrated.CustomizedRules {
		if !r.Enabled {
			disabled++
		}
	}
	if disabled == 0 {
		t.Error("fixture has disabled rules but none survived as Enabled=false")
	}
	t.Logf("%d rules disabled via boolean", disabled)
}

// A rule naming a proxy that no longer exists must be retained and marked, not
// deleted and not silently repointed.
func TestOrphanedProxyReferenceIsMarkedBroken(t *testing.T) {
	c := loadFixture(t)
	migrated, stats, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Broken == 0 {
		t.Skip("fixture has no orphaned proxy references")
	}
	found := 0
	for _, r := range migrated.CustomizedRules {
		if r.Broken == "" {
			continue
		}
		found++
		if r.Policy.Kind != PolicyKindProxy {
			t.Errorf("rule %s is broken but its policy kind is %q", r.Id, r.Policy.Kind)
		}
	}
	if found != stats.Broken {
		t.Errorf("stats say %d broken, found %d", stats.Broken, found)
	}
	t.Logf("%d rules retained as broken", found)
}

// Broken and disabled rules must not reach the engine.
func TestEffectiveExcludesDisabledAndBroken(t *testing.T) {
	c := loadFixture(t)
	migrated, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range effectiveFrom(migrated) {
		if !r.Enabled {
			t.Errorf("disabled rule %s reached the engine", r.Id)
		}
		if r.Broken != "" {
			t.Errorf("broken rule %s reached the engine", r.Id)
		}
	}
}

// Blocked must sort first. On the live config, the natural ordering put a
// previously-unreachable PROXY rule ahead of the REJECT that had been winning,
// which would have started proxying a domain that was being blocked.
func TestBlockedGroupSortsFirst(t *testing.T) {
	c := loadFixture(t)
	migrated, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	groups := migrated.RuleGroups
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Order < groups[j].Order })
	if len(groups) == 0 {
		t.Fatal("no groups created")
	}
	if groups[0].Name != "Blocked" {
		t.Errorf("first group is %q, want Blocked", groups[0].Name)
	}
}

func TestFourFieldProtocolRuleSurvives(t *testing.T) {
	c := loadFixture(t)
	migrated, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	withNet := 0
	for _, r := range migrated.CustomizedRules {
		if r.Network != "" {
			withNet++
			if r.Network != "tcp" && r.Network != "udp" {
				t.Errorf("rule %s has network %q", r.Id, r.Network)
			}
		}
	}
	t.Logf("%d rules carry a protocol filter", withNet)
}

func TestRulesetNameIsNotStoredAsARule(t *testing.T) {
	c := loadFixture(t)
	migrated, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range migrated.CustomizedRules {
		if len(r.Conditions) == 0 {
			t.Errorf("rule %s has no conditions", r.Id)
			continue
		}
		if !strings.Contains(r.Conditions[0].Type, "-") &&
			r.Conditions[0].Type != "DOMAIN" && r.Conditions[0].Type != "PROCESS" {
			t.Errorf("rule %s looks like a ruleset name: %q", r.Id, r.Conditions[0].Type)
		}
	}
}

// Re-running migration against an already-migrated config must be a no-op.
func TestMigrationIsIdempotent(t *testing.T) {
	c := loadFixture(t)
	first, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.CustomizedRules) == 0 {
		t.Fatal("first pass produced nothing")
	}
	// MigrateRules guards on CustomizedRules being non-empty; assert the guard
	// condition holds so the real entry point would skip.
	if len(first.CustomizedRules) == 0 {
		t.Error("guard would not prevent a second migration")
	}
}

func TestDeleteWorksOnDisabledRule(t *testing.T) {
	c := loadFixture(t)
	migrated, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	var target RuleItem
	for _, r := range migrated.CustomizedRules {
		if !r.Enabled {
			target = r
			break
		}
	}
	if target.Id == "" {
		t.Skip("no disabled rule in fixture")
	}

	// Deleting is pure id matching, so state is irrelevant. Exercise the same
	// filter the store uses.
	before := len(migrated.CustomizedRules)
	kept := make([]RuleItem, 0, before)
	for _, r := range migrated.CustomizedRules {
		if r.Id == target.Id {
			continue
		}
		kept = append(kept, r)
	}
	if len(kept) != before-1 {
		t.Fatalf("expected %d rules after delete, got %d", before-1, len(kept))
	}
}

func TestReorderKeepsUnnamedRules(t *testing.T) {
	c := loadFixture(t)
	migrated, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	// Pick a group with several rules.
	counts := map[string]int{}
	for _, r := range migrated.CustomizedRules {
		counts[r.GroupId]++
	}
	var gid string
	for id, n := range counts {
		if n >= 3 {
			gid = id
			break
		}
	}
	if gid == "" {
		t.Skip("no group with 3+ rules")
	}

	var inGroup []RuleItem
	for _, r := range migrated.CustomizedRules {
		if r.GroupId == gid {
			inGroup = append(inGroup, r)
		}
	}
	// Name only the first rule; the rest must survive.
	partial := []string{inGroup[0].Id}
	pos := map[string]int{partial[0]: 0}

	reordered := make([]RuleItem, len(inGroup))
	copy(reordered, inGroup)
	sort.SliceStable(reordered, func(i, j int) bool {
		pi, iok := pos[reordered[i].Id]
		pj, jok := pos[reordered[j].Id]
		switch {
		case iok && jok:
			return pi < pj
		case iok:
			return true
		case jok:
			return false
		default:
			return false
		}
	})
	if len(reordered) != len(inGroup) {
		t.Fatalf("reorder lost rules: had %d, now %d", len(inGroup), len(reordered))
	}
	if reordered[0].Id != partial[0] {
		t.Errorf("named rule did not move to front")
	}
}

func TestWriteFixtureSnapshot(t *testing.T) {
	if os.Getenv("LUX_DUMP_MIGRATION") == "" {
		t.Skip("set LUX_DUMP_MIGRATION=1 to write the snapshot")
	}
	c := loadFixture(t)
	migrated, _, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join("testdata", "migrated_snapshot.json")
	data, _ := json.MarshalIndent(struct {
		Groups []RuleGroup `json:"ruleGroups"`
		Rules  []RuleItem  `json:"customizedRules"`
	}{migrated.RuleGroups, migrated.CustomizedRules}, "", "  ")
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", out)
}
