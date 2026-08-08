package configuration

import (
	"fmt"
	"os"
	"sort"
	"testing"
)

// TestPreviewMigration prints the full grouping outcome for the fixture.
// Not an assertion — a readable report for reviewing the classifier.
func TestPreviewMigration(t *testing.T) {
	if os.Getenv("LUX_PREVIEW") == "" {
		t.Skip("set LUX_PREVIEW=1 to print the migration preview")
	}
	c := loadFixture(t)
	migrated, stats, err := convertLegacyRules(c, c.Rules)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("\nconverted=%d disabled=%d deduped=%d quarantined=%d broken=%d ruleset=%q\n\n",
		stats.Converted, stats.Disabled, stats.Deduped, stats.Quarantined, stats.Broken,
		migrated.SelectedRuleset)

	groups := migrated.RuleGroups
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Order < groups[j].Order })

	for _, g := range groups {
		var rs []RuleItem
		for _, r := range migrated.CustomizedRules {
			if r.GroupId == g.Id {
				rs = append(rs, r)
			}
		}
		if len(rs) == 0 {
			continue
		}
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].Order < rs[j].Order })
		fmt.Printf("=== %s (%d) ===\n", g.Name, len(rs))
		for _, r := range rs {
			state := "on "
			if !r.Enabled {
				state = "OFF"
			}
			net := ""
			if r.Network != "" {
				net = " [" + r.Network + "]"
			}
			broken := ""
			if r.Broken != "" {
				broken = "   <-- BROKEN"
			}
			fmt.Printf("  %s %-4s %-46s -> %-10s%s%s\n",
				state, r.Id,
				r.Conditions[0].Type+","+r.Conditions[0].Value,
				PolicyLabel(r.Policy, migrated), net, broken)
		}
		fmt.Println()
	}
}
