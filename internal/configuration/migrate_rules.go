package configuration

// Migration from the legacy []string rule list to the id-keyed store.
//
// The legacy format encoded three things in one string: the rule definition, its
// identity, and its enabled state (via a leading "#"). Migration decomposes
// that, assigns stable ids, and sorts rules into groups.
//
// Grouping reorders the flattened evaluation sequence, and reordering changes
// which rule wins. That makes this migration capable of silently altering
// routing, so it ends with a verification pass that replays every payload
// through the old and new sequences and aborts on any divergence.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/igoogolx/itun2socks/pkg/log"
)

// Group names created by migration. Blocked is deliberately first: REJECT rules
// are terminal denials and must not be shadowed by a later allow. Ordering it
// last would, on a real config, have let a previously-dead PROXY rule start
// winning over the REJECT above it.
var migrationGroups = []string{
	"Blocked",
	"Local & LAN",
	"Preproxy",
	"AI tools",
	"Remote desktop",
	"Mail",
	"Parallels",
	"Congregatio intranet",
	"Other",
}

type migrationStats struct {
	Converted   int
	Disabled    int
	Deduped     int
	Quarantined int
	Broken      int
	Rulesets    int
}

// MigrateRules converts a legacy config in place. It is a no-op when the store
// is already populated, which makes it idempotent.
func MigrateRules() error {
	c, err := Read()
	if err != nil {
		return err
	}
	if len(c.CustomizedRules) > 0 {
		return nil
	}
	if len(c.Rules) == 0 {
		return nil
	}

	if err := backupConfig(); err != nil {
		// A failed backup must stop the migration: without it there is no way
		// back from a bad conversion.
		return fmt.Errorf("refusing to migrate without a backup: %w", err)
	}

	legacy := make([]string, len(c.Rules))
	copy(legacy, c.Rules)

	migrated, stats, err := convertLegacyRules(c, legacy)
	if err != nil {
		return err
	}

	if err := verifyMigration(legacy, migrated); err != nil {
		return fmt.Errorf("migration changed routing, aborting: %w", err)
	}

	migrated.Rules = legacy
	syncLegacyRules(&migrated)

	if err := Write(migrated); err != nil {
		return err
	}

	log.Infoln(log.FormatLog(log.ConfigurationPrefix,
		"migrated rules: %d converted, %d disabled, %d deduplicated, %d quarantined, %d broken, %d rulesets"),
		stats.Converted, stats.Disabled, stats.Deduped, stats.Quarantined, stats.Broken, stats.Rulesets)
	return nil
}

func backupConfig() error {
	path, err := GetConfigFilePath()
	if err != nil || path == "" {
		return fmt.Errorf("no config path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dst := fmt.Sprintf("%s.bak.%d", path, time.Now().Unix())
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	log.Infoln(log.FormatLog(log.ConfigurationPrefix, "backed up config to %v"), dst)
	return nil
}

// convertLegacyRules does the structural conversion. It returns a new Config
// rather than mutating, so the caller can discard it if verification fails.
func convertLegacyRules(base Config, legacy []string) (Config, migrationStats, error) {
	out := base
	out.CustomizedRules = nil
	out.RuleGroups = nil
	out.QuarantinedRules = nil
	out.NextRuleId = 1
	out.NextGroupId = 1

	groupIds := make(map[string]string, len(migrationGroups))
	for _, name := range migrationGroups {
		id := nextGroupId(&out)
		out.RuleGroups = append(out.RuleGroups, RuleGroup{
			Id:      id,
			Name:    name,
			Enabled: true,
			Order:   len(out.RuleGroups),
		})
		groupIds[name] = id
	}

	var stats migrationStats
	seen := make(map[string]int) // conditionKey -> index into out.CustomizedRules

	for order, raw := range legacy {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		enabled := !strings.HasPrefix(trimmed, "#")
		body := strings.TrimLeft(trimmed, "#")
		body = strings.TrimSpace(body)

		// An entry without a comma is a built-in ruleset name, not a rule.
		// Storing these in the same array is what forced the engine to tell
		// rules from ruleset names by looking for a comma.
		if !strings.Contains(body, ",") {
			out.SelectedRuleset = body
			stats.Rulesets++
			continue
		}

		chunks := strings.Split(body, ",")
		for i := range chunks {
			chunks[i] = strings.TrimSpace(chunks[i])
		}
		if len(chunks) < 3 {
			out.QuarantinedRules = append(out.QuarantinedRules, raw)
			stats.Quarantined++
			log.Warnln(log.FormatLog(log.ConfigurationPrefix, "quarantined unparseable rule: %v"), raw)
			continue
		}

		item := RuleItem{
			Conditions: []RuleCondition{{Type: chunks[0], Value: chunks[1]}},
			Enabled:    enabled,
			Order:      order,
		}
		if len(chunks) >= 4 {
			switch strings.ToLower(chunks[3]) {
			case "tcp":
				item.Network = "tcp"
			case "udp":
				item.Network = "udp"
			}
		}

		item.Policy = resolveLegacyPolicy(out, chunks[2])
		if item.Policy.Kind == PolicyKindProxy && item.Policy.ProxyId == "" {
			// A name that matches neither a built-in nor an existing proxy.
			// Almost always the residue of a deleted proxy. Keep the rule,
			// mark it, and do not guess a replacement.
			item.Policy.ProxyId = chunks[2]
			item.Broken = fmt.Sprintf("proxy %q no longer exists", chunks[2])
			stats.Broken++
			log.Warnln(log.FormatLog(log.ConfigurationPrefix,
				"rule references unknown proxy %q, keeping it but marking broken: %v"), chunks[2], raw)
		}

		if !enabled {
			stats.Disabled++
		}

		key := conditionKey(item)
		if prev, dup := seen[key]; dup {
			// Prefer the enabled copy. Under the legacy format an enabled and a
			// disabled copy of the same rule were different strings, so both
			// could coexist and appear as duplicate rows.
			if item.Enabled && !out.CustomizedRules[prev].Enabled {
				out.CustomizedRules[prev].Enabled = true
			}
			stats.Deduped++
			continue
		}

		item.Id = nextRuleId(&out)
		item.GroupId = groupIds[classify(item)]
		out.CustomizedRules = append(out.CustomizedRules, item)
		seen[key] = len(out.CustomizedRules) - 1
		stats.Converted++
	}

	// Slugs are assigned after all rules exist so disambiguation sees the whole
	// set.
	taken := make(map[string]bool, len(out.CustomizedRules))
	for i := range out.CustomizedRules {
		base := makeSlug(out.CustomizedRules[i], out)
		s := uniqueSlug(base, taken)
		out.CustomizedRules[i].Slug = s
		taken[s] = true
	}

	// Renumber Order within each group, preserving the relative order inherited
	// from the legacy array.
	byGroup := make(map[string][]int)
	for i, r := range out.CustomizedRules {
		byGroup[r.GroupId] = append(byGroup[r.GroupId], i)
	}
	for _, idxs := range byGroup {
		sort.SliceStable(idxs, func(a, b int) bool {
			return out.CustomizedRules[idxs[a]].Order < out.CustomizedRules[idxs[b]].Order
		})
		for pos, idx := range idxs {
			out.CustomizedRules[idx].Order = pos
		}
	}

	return out, stats, nil
}

// resolveLegacyPolicy maps a legacy policy string onto a RulePolicy.
//
// A name that is neither built-in nor a current proxy yields Kind=proxy with an
// empty ProxyId, which the caller turns into a broken rule.
// Comparison is case-sensitive on purpose. rule_engine.ParseItem compares the
// policy against "DIRECT"/"REJECT"/"PROXY" exactly, so a legacy entry reading
// "Proxy" was rejected by the engine and the rule never matched anything.
// Folding case here would quietly resurrect such a rule and change routing.
func resolveLegacyPolicy(c Config, raw string) RulePolicy {
	switch raw {
	case "DIRECT":
		return RulePolicy{Kind: PolicyKindDirect}
	case "REJECT":
		return RulePolicy{Kind: PolicyKindReject}
	case "PROXY":
		return RulePolicy{Kind: PolicyKindSelected}
	}
	// A proxy may legitimately be named "Proxy", so this lookup is also
	// case-sensitive and must come after the built-ins.
	if id := proxyIdByName(c, raw); id != "" {
		return RulePolicy{Kind: PolicyKindProxy, ProxyId: id}
	}
	return RulePolicy{Kind: PolicyKindProxy}
}

// engineAcceptsPolicy reports whether the legacy engine would have accepted this
// policy string. Used by verification to model the old behaviour faithfully: a
// rule the engine rejected contributed nothing, so it must contribute nothing on
// the legacy side of the comparison either.
func engineAcceptsPolicy(c Config, raw string) bool {
	switch raw {
	case "DIRECT", "REJECT", "PROXY":
		return true
	}
	return proxyIdByName(c, raw) != ""
}

// classify assigns a group. Predicates run in order, first match wins, and
// anything unmatched lands in "Other" rather than being guessed at.
func classify(r RuleItem) string {
	if r.Policy.Kind == PolicyKindReject {
		return "Blocked"
	}

	cond := r.Conditions[0]
	t := strings.ToUpper(cond.Type)
	v := strings.ToLower(cond.Value)

	if t == "IP-CIDR" && isPrivateCidr(v) {
		return "Local & LAN"
	}
	if v == "localhost" || strings.HasPrefix(v, "127.0.0.1") {
		return "Local & LAN"
	}
	if strings.Contains(v, "preproxy") {
		return "Preproxy"
	}
	if containsAny(v, "anthropic", "claude", "kiro.dev", "antigravity", "cloudcode",
		"codewhisperer", "bedrock", "amazonq", "cognito", "codeium",
		"language_server", "oauth-success", "sts.amazonaws") {
		return "AI tools"
	}
	if containsAny(v, "rustdesk", "anydesk") {
		return "Remote desktop"
	}
	if containsAny(v, "parallels", "myparallels") {
		return "Parallels"
	}
	if containsAny(v, "icloud", "gmail", "1e100", "apple") || strings.HasPrefix(v, "mail") ||
		v == "mail.app" || strings.Contains(v, "maild") || strings.Contains(v, "icloudmailagent") {
		return "Mail"
	}
	if strings.Contains(v, "congregatio") {
		return "Congregatio intranet"
	}
	return "Other"
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func isPrivateCidr(v string) bool {
	return strings.HasPrefix(v, "10.") ||
		strings.HasPrefix(v, "192.168.") ||
		strings.HasPrefix(v, "172.16.") ||
		strings.HasPrefix(v, "172.17.") ||
		strings.HasPrefix(v, "172.18.") ||
		strings.HasPrefix(v, "172.19.") ||
		strings.HasPrefix(v, "172.2") ||
		strings.HasPrefix(v, "172.30.") ||
		strings.HasPrefix(v, "172.31.") ||
		strings.HasPrefix(v, "127.") ||
		strings.HasPrefix(v, "169.254.")
}

// ── Verification ────────────────────────────────────────────────────────────

// verifyMigration replays every rule payload through the legacy sequence and the
// new flattened sequence and requires the same policy from both.
//
// This is the gate that makes grouping safe. Without it, moving rules into groups
// silently reorders evaluation, and a rule that never matched can start winning.
func verifyMigration(legacy []string, migrated Config) error {
	type probe struct {
		condType string
		value    string
		network  string
	}

	var probes []probe
	for _, raw := range legacy {
		body := strings.TrimLeft(strings.TrimSpace(raw), "#")
		if !strings.Contains(body, ",") {
			continue
		}
		chunks := strings.Split(body, ",")
		if len(chunks) < 3 {
			continue
		}
		p := probe{
			condType: strings.TrimSpace(chunks[0]),
			value:    strings.TrimSpace(chunks[1]),
		}
		if len(chunks) >= 4 {
			p.network = strings.ToLower(strings.TrimSpace(chunks[3]))
		}
		probes = append(probes, p)
	}

	effective := effectiveFrom(migrated)

	for _, p := range probes {
		want, wantFound := legacyDecision(legacy, migrated, p.condType, p.value, p.network)
		got, gotFound := storeDecision(effective, p.condType, p.value, p.network)

		if wantFound != gotFound {
			return fmt.Errorf("payload %s,%s: legacy matched=%v, store matched=%v",
				p.condType, p.value, wantFound, gotFound)
		}
		if wantFound && want != got {
			return fmt.Errorf("payload %s,%s: legacy gave %q, store gives %q",
				p.condType, p.value, want, got)
		}
	}
	return nil
}

// legacyDecision walks the legacy array the way the old engine did: in array
// order, skipping "#"-prefixed entries, first match wins.
func legacyDecision(legacy []string, c Config, condType, value, network string) (string, bool) {
	for _, raw := range legacy {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		chunks := strings.Split(trimmed, ",")
		if len(chunks) < 3 {
			continue
		}
		for i := range chunks {
			chunks[i] = strings.TrimSpace(chunks[i])
		}
		if !strings.EqualFold(chunks[0], condType) || chunks[1] != value {
			continue
		}
		// The legacy engine discarded rules whose policy it could not parse, so
		// such a rule never won a match and must be skipped here too.
		if !engineAcceptsPolicy(c, chunks[2]) {
			continue
		}
		ruleNet := ""
		if len(chunks) >= 4 {
			ruleNet = strings.ToLower(chunks[3])
		}
		if ruleNet != "" && network != "" && ruleNet != network {
			continue
		}
		return normalisePolicyLabel(c, chunks[2]), true
	}
	return "", false
}

// storeDecision walks the new flattened sequence the same way.
func storeDecision(effective []RuleItem, condType, value, network string) (string, bool) {
	for _, r := range effective {
		if len(r.Conditions) == 0 {
			continue
		}
		cond := r.Conditions[0]
		if !strings.EqualFold(cond.Type, condType) || cond.Value != value {
			continue
		}
		if r.Network != "" && network != "" && r.Network != network {
			continue
		}
		return string(r.PolicyValue()), true
	}
	return "", false
}

// normalisePolicyLabel renders a legacy policy string the way PolicyValue would,
// so the two sides of the comparison are expressed identically.
func normalisePolicyLabel(c Config, raw string) string {
	switch raw {
	case "DIRECT", "REJECT", "PROXY":
		return raw
	}
	if id := proxyIdByName(c, raw); id != "" {
		return id
	}
	return raw
}

// DumpMigrationPreview renders what migration would do, without writing. Useful
// for inspecting the outcome against a real config before committing to it.
func DumpMigrationPreview() (string, error) {
	c, err := Read()
	if err != nil {
		return "", err
	}
	legacy := make([]string, len(c.Rules))
	copy(legacy, c.Rules)

	migrated, stats, err := convertLegacyRules(c, legacy)
	if err != nil {
		return "", err
	}
	verifyErr := verifyMigration(legacy, migrated)

	var b strings.Builder
	fmt.Fprintf(&b, "converted=%d disabled=%d deduped=%d quarantined=%d broken=%d rulesets=%d\n",
		stats.Converted, stats.Disabled, stats.Deduped, stats.Quarantined, stats.Broken, stats.Rulesets)
	if verifyErr != nil {
		fmt.Fprintf(&b, "VERIFICATION FAILED: %v\n", verifyErr)
	} else {
		fmt.Fprintf(&b, "verification passed\n")
	}
	fmt.Fprintf(&b, "selectedRuleset=%q\n\n", migrated.SelectedRuleset)

	for _, g := range migrated.RuleGroups {
		var rs []RuleItem
		for _, r := range migrated.CustomizedRules {
			if r.GroupId == g.Id {
				rs = append(rs, r)
			}
		}
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].Order < rs[j].Order })
		fmt.Fprintf(&b, "[%s] %s (%d rules)\n", g.Id, g.Name, len(rs))
		for _, r := range rs {
			state := " "
			if !r.Enabled {
				state = "x"
			}
			broken := ""
			if r.Broken != "" {
				broken = "  BROKEN: " + r.Broken
			}
			fmt.Fprintf(&b, "  [%s] %-4s %-28s -> %-12s %s%s\n",
				state, r.Id, r.Conditions[0].Type+","+r.Conditions[0].Value,
				r.PolicyValue(), r.Slug, broken)
		}
		b.WriteString("\n")
	}

	if len(migrated.QuarantinedRules) > 0 {
		b.WriteString("quarantined:\n")
		for _, q := range migrated.QuarantinedRules {
			fmt.Fprintf(&b, "  %s\n", q)
		}
	}

	data, _ := json.MarshalIndent(migrated.RuleGroups, "", "  ")
	fmt.Fprintf(&b, "\ngroups json:\n%s\n", data)
	return b.String(), nil
}
