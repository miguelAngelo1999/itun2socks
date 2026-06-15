package configuration

import (
	"fmt"
	"slices"
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

func AddCustomizedRule(rules []string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	for _, rule := range rules {
		formatedRule := strings.TrimSpace(rule)
		targetIndex := slices.Index(c.Rules, formatedRule)
		if targetIndex != -1 {
			return fmt.Errorf("duplicated rule: %v", rule)
		}
		_, err = rule_engine.ParseRawValue(formatedRule)
		if err != nil {
			return err
		}
		c.Rules = append(c.Rules, formatedRule)
	}

	return Write(c)
}

func DeleteCustomizedRule(rules []string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	for _, rule := range rules {
		_, err = rule_engine.ParseRawValue(rule)
		if err != nil {
			return err
		}
		var newRules []string
		for _, item := range c.Rules {
			if item != rule {
				newRules = append(newRules, item)
			}
		}
		c.Rules = newRules
	}
	return Write(c)
}

func GetCustomizedRules() ([]rule_engine.Rule, error) {
	c, err := Read()
	if err != nil {
		return nil, err
	}
	var items []rule_engine.Rule
	for _, rule := range c.Rules {
		item, err := rule_engine.ParseRawValue(rule)
		if err == nil {
			items = append(items, item)
		}
	}
	return items, nil
}

func EditCustomizedRule(oldRule string, newRule string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	targetIndex := slices.Index(c.Rules, oldRule)
	if targetIndex != -1 {
		slices.Replace(c.Rules, targetIndex, targetIndex+1, newRule)
	}
	return Write(c)
}

func GetBuiltInRules(id string) ([]rule_engine.Rule, error) {
	return rule_engine.Parse(id, []string{})
}

// ReorderCustomizedRules replaces the full ordered list of customized rules.
// Used by the UI up/down arrows to reorder rules.
func ReorderCustomizedRules(rules []string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	// Validate each rule (skip disabled ones starting with #)
	for _, rule := range rules {
		trimmed := strings.TrimSpace(rule)
		if strings.HasPrefix(trimmed, "#") {
			continue // disabled rule, skip validation
		}
		if _, err := rule_engine.ParseRawValue(trimmed); err != nil {
			return fmt.Errorf("invalid rule %q: %v", trimmed, err)
		}
	}
	// Replace only customized rules, keeping built-in ruleset selections
	var newRules []string
	for _, r := range c.Rules {
		// Keep built-in rules (non-custom format)
		if !strings.Contains(r, ",") {
			newRules = append(newRules, r)
		}
	}
	// Prepend built-ins, append new custom order
	c.Rules = append(newRules, rules...)
	return Write(c)
}

// ToggleCustomizedRule toggles a rule between enabled (#-prefixed) and disabled.
func ToggleCustomizedRule(rule string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(rule)
	// Strip ALL leading # to get the base rule
	baseRule := strings.TrimLeft(trimmed, "#")

	for i, r := range c.Rules {
		rBase := strings.TrimLeft(strings.TrimSpace(r), "#")
		if rBase != baseRule {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(r), "#") {
			// Currently disabled -> enable (remove all # prefixes)
			c.Rules[i] = baseRule
		} else {
			// Currently enabled -> disable (add single #)
			c.Rules[i] = "#" + baseRule
		}
		return Write(c)
	}
	return fmt.Errorf("rule not found: %s", rule)
}

// GetCustomizedRulesRaw returns all customized rules as structured items,
// including disabled ones (prefixed with #) with a disabled flag.
// Supports both 3-field (TYPE,MATCH,ACTION) and 4-field (TYPE,MATCH,ACTION,PROTOCOL) rules.
func GetCustomizedRulesRaw() ([]map[string]any, error) {
	c, err := Read()
	if err != nil {
		return nil, err
	}
	var items []map[string]any
	for _, rule := range c.Rules {
		trimmed := strings.TrimSpace(rule)
		disabled := strings.HasPrefix(trimmed, "#")
		rawRule := strings.TrimLeft(trimmed, "#") // strip ALL leading #s
		chunks := strings.Split(rawRule, ",")
		if len(chunks) < 3 {
			continue // skip built-in rule names (no commas) or malformed rules
		}
		item := map[string]any{
			"ruleType": strings.TrimSpace(chunks[0]),
			"payload":  strings.TrimSpace(chunks[1]),
			"policy":   strings.TrimSpace(chunks[2]),
			"disabled": disabled,
			"raw":      trimmed,
		}
		// Include optional 4th field as "network" (protocol filter: "tcp" or "udp")
		if len(chunks) >= 4 {
			proto := strings.ToLower(strings.TrimSpace(chunks[3]))
			if proto == "tcp" || proto == "udp" {
				item["network"] = proto
			}
		}
		items = append(items, item)
	}
	return items, nil
}
