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

// ToggleCustomizedRule toggles a rule between enabled and disabled (# prefix).
func ToggleCustomizedRule(rule string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(rule)
	for i, r := range c.Rules {
		if r == trimmed {
			// Enable -> disable
			c.Rules[i] = "#" + trimmed
			return Write(c)
		}
		if r == "#"+trimmed || "#"+r == trimmed {
			// Disable -> enable (strip #)
			stripped := strings.TrimPrefix(r, "#")
			if stripped == "" {
				stripped = strings.TrimPrefix(trimmed, "#")
			}
			c.Rules[i] = stripped
			return Write(c)
		}
	}
	return fmt.Errorf("rule not found: %s", rule)
}

// GetCustomizedRulesRaw returns all customized rules as structured items,
// including disabled ones (prefixed with #) with a disabled flag.
func GetCustomizedRulesRaw() ([]map[string]any, error) {
	c, err := Read()
	if err != nil {
		return nil, err
	}
	var items []map[string]any
	for _, rule := range c.Rules {
		trimmed := strings.TrimSpace(rule)
		disabled := strings.HasPrefix(trimmed, "#")
		rawRule := trimmed
		if disabled {
			rawRule = strings.TrimPrefix(trimmed, "#")
		}
		chunks := strings.Split(rawRule, ",")
		if len(chunks) != 3 {
			continue // skip built-in rule names (no commas)
		}
		items = append(items, map[string]any{
			"ruleType": strings.TrimSpace(chunks[0]),
			"payload":  strings.TrimSpace(chunks[1]),
			"policy":   strings.TrimSpace(chunks[2]),
			"disabled": disabled,
			"raw":      trimmed,
		})
	}
	return items, nil
}
