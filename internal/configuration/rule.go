package configuration

// Legacy rule API, reimplemented over the id-keyed store in rule_store.go.
//
// These functions exist so the embedded web dashboard and any other caller that
// speaks in rule strings keeps working. Each one resolves the string to a rule id
// and then performs the operation by id, which is what makes the historic bugs go
// away: matching happens on structure rather than on a string whose content
// doubles as its identity.
//
// New code should use the store directly.

import (
	"fmt"
	"strings"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
)

func GetSelectedRule() (string, error) {
	c, err := Read()
	if err != nil {
		return "", err
	}
	return c.Selected.Rule, nil
}

func GetRuleIds() ([]string, error) {
	return rule_engine.GetRuleIds()
}

// KnownProxyIds lists the proxy ids a rule may target.
func KnownProxyIds() ([]string, error) {
	c, err := Read()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(c.Proxy))
	for _, p := range c.Proxy {
		if id := fmt.Sprint(p["id"]); id != "" && id != "<nil>" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// parseRawToItem converts a rule string into a RuleItem, resolving the policy
// against the current proxies. A leading "#" is honoured so callers still using
// the old convention keep working.
func parseRawToItem(c Config, raw string) (RuleItem, error) {
	trimmed := strings.TrimSpace(raw)
	enabled := !strings.HasPrefix(trimmed, "#")
	body := strings.TrimSpace(strings.TrimLeft(trimmed, "#"))

	chunks := strings.Split(body, ",")
	if len(chunks) < 3 {
		return RuleItem{}, fmt.Errorf("invalid rule: %q", raw)
	}
	for i := range chunks {
		chunks[i] = strings.TrimSpace(chunks[i])
	}

	item := RuleItem{
		Conditions: []RuleCondition{{Type: chunks[0], Value: chunks[1]}},
		Enabled:    enabled,
		Policy:     resolveLegacyPolicy(c, chunks[2]),
	}
	if len(chunks) >= 4 {
		switch strings.ToLower(chunks[3]) {
		case "tcp":
			item.Network = "tcp"
		case "udp":
			item.Network = "udp"
		default:
			return RuleItem{}, fmt.Errorf("unknown protocol %q in rule %q", chunks[3], raw)
		}
	}
	if item.Policy.Kind == PolicyKindProxy && item.Policy.ProxyId == "" {
		return RuleItem{}, fmt.Errorf("rule %q targets unknown policy %q", raw, chunks[2])
	}
	return item, nil
}

// findRuleByRaw locates a stored rule matching a rule string.
//
// Matching ignores enabled state and any "#" prefix, so a caller holding the
// disabled form of a rule still finds it. Under the old implementation the
// prefix made the strings unequal, which is why deleting a disabled rule could
// never find its target.
func findRuleByRaw(c Config, raw string) (RuleItem, bool) {
	candidate, err := parseRawToItem(c, raw)
	if err != nil {
		return RuleItem{}, false
	}
	key := conditionKey(candidate)
	for _, r := range c.CustomizedRules {
		if conditionKey(r) == key {
			return r, true
		}
	}
	return RuleItem{}, false
}

func AddCustomizedRule(rules []string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	for _, raw := range rules {
		item, err := parseRawToItem(c, raw)
		if err != nil {
			return err
		}
		if _, err := CreateRule(item); err != nil {
			return err
		}
		// CreateRule persists, so re-read to keep subsequent duplicate checks
		// and id assignment consistent across a multi-rule request.
		c, err = Read()
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteCustomizedRule removes rules given in string form.
//
// The rule is resolved to an id first, so this succeeds for disabled rules. The
// previous implementation validated the incoming string with ParseRawValue
// before matching, which rejected the "#" prefix outright and returned an error
// without touching the list — the UI then removed the row optimistically, hit the
// error, reloaded, and the rule reappeared.
func DeleteCustomizedRule(rules []string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(rules))
	for _, raw := range rules {
		item, found := findRuleByRaw(c, raw)
		if !found {
			return fmt.Errorf("%w: %s", ErrRuleNotFound, raw)
		}
		ids = append(ids, item.Id)
	}
	return DeleteRule(ids)
}

func GetCustomizedRules() ([]rule_engine.Rule, error) {
	effective, err := EffectiveRules()
	if err != nil {
		return nil, err
	}
	knownIds, err := KnownProxyIds()
	if err != nil {
		return nil, err
	}
	var items []rule_engine.Rule
	for _, r := range effective {
		rule, _, err := rule_engine.ParseRawValueWithPolicies(r.RawValue(), knownIds)
		if err == nil {
			items = append(items, rule)
		}
	}
	return items, nil
}

// EditCustomizedRule replaces one rule's content.
//
// The old implementation computed slices.Replace and discarded its result, so
// editing silently did nothing while reporting success. It also failed to report
// a missing target at all.
func EditCustomizedRule(oldRule string, newRule string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	existing, found := findRuleByRaw(c, oldRule)
	if !found {
		return fmt.Errorf("%w: %s", ErrRuleNotFound, oldRule)
	}
	updated, err := parseRawToItem(c, newRule)
	if err != nil {
		return err
	}
	// An edit changes content, never state: toggling is a separate operation.
	updated.Enabled = existing.Enabled
	return UpdateRule(existing.Id, updated)
}

func GetBuiltInRules(id string) ([]rule_engine.Rule, error) {
	return rule_engine.Parse(id, []string{})
}

// ReorderCustomizedRules applies a new order given in string form.
//
// The previous implementation rebuilt the whole array from the caller's payload
// and told built-in ruleset names from rules by checking for a comma, so any rule
// the caller omitted was silently dropped. Ruleset names now live in their own
// field, and rules absent from the request keep their position.
func ReorderCustomizedRules(rules []string) error {
	c, err := Read()
	if err != nil {
		return err
	}

	// Group the requested order by the group each rule belongs to, so a flat
	// legacy payload still produces a sensible per-group ordering.
	perGroup := map[string][]string{}
	for _, raw := range rules {
		item, found := findRuleByRaw(c, raw)
		if !found {
			continue
		}
		perGroup[item.GroupId] = append(perGroup[item.GroupId], item.Id)
	}
	for groupId, ids := range perGroup {
		if err := ReorderRules(groupId, ids); err != nil {
			return err
		}
	}
	return nil
}

// ToggleCustomizedRule flips a rule's enabled flag, given in string form.
func ToggleCustomizedRule(raw string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	item, found := findRuleByRaw(c, raw)
	if !found {
		return fmt.Errorf("%w: %s", ErrRuleNotFound, raw)
	}
	return ToggleRule(item.Id)
}

// GetCustomizedRulesRaw returns every rule, including disabled and broken ones,
// in the shape the UI consumes.
//
// "raw" is generated from the structured fields and never carries a "#": state is
// reported by the separate "disabled" field. Emitting a prefix here is what let
// clients send it back as an identity.
func GetCustomizedRulesRaw() ([]map[string]any, error) {
	c, err := Read()
	if err != nil {
		return nil, err
	}

	ordered := orderedForDisplay(c)
	items := make([]map[string]any, 0, len(ordered))
	for _, r := range ordered {
		if len(r.Conditions) == 0 {
			continue
		}
		item := map[string]any{
			"id":       r.Id,
			"slug":     r.Slug,
			"groupId":  r.GroupId,
			"ruleType": r.Conditions[0].Type,
			"payload":  r.Conditions[0].Value,
			"policy":   PolicyLabel(r.Policy, c),
			"disabled": !r.Enabled,
			"raw":      r.RawValue(),
			"order":    r.Order,
		}
		if r.Network != "" {
			item["network"] = r.Network
		}
		if r.Broken != "" {
			item["broken"] = r.Broken
		}
		if len(r.Conditions) > 1 {
			conds := make([]map[string]string, 0, len(r.Conditions))
			for _, cond := range r.Conditions {
				conds = append(conds, map[string]string{"type": cond.Type, "value": cond.Value})
			}
			item["conditions"] = conds
		}
		items = append(items, item)
	}
	return items, nil
}

// orderedForDisplay lists every rule in evaluation order, including the disabled
// and broken ones that EffectiveRules omits.
func orderedForDisplay(c Config) []RuleItem {
	groups := make([]RuleGroup, len(c.RuleGroups))
	copy(groups, c.RuleGroups)
	sortGroupsByOrder(groups)

	var out []RuleItem
	appendGroup := func(gid string) {
		var rs []RuleItem
		for _, r := range c.CustomizedRules {
			if r.GroupId == gid {
				rs = append(rs, r)
			}
		}
		sortRulesByOrder(rs)
		out = append(out, rs...)
	}
	for _, g := range groups {
		appendGroup(g.Id)
	}
	appendGroup(DefaultGroupId)
	return out
}
