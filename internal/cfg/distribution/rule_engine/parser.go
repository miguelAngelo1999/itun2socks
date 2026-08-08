package rule_engine

import (
	"embed"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/list"
	"github.com/igoogolx/itun2socks/pkg/log"
)

//go:embed rules/*
var data embed.FS

func trimArr(arr []string) (r []string) {
	for _, e := range arr {
		r = append(r, strings.TrimSpace(e))
	}
	return
}

func GetRuleIds() ([]string, error) {
	ruleFiles, err := data.ReadDir("rules")
	var rules []string
	if err != nil {
		return nil, err
	}
	for _, rule := range ruleFiles {
		rules = append(rules, rule.Name())
	}
	return rules, err
}

func Parse(name string, extraRules []string) ([]Rule, error) {
	parsed, err := ParseToParsedRules(name, extraRules)
	if err != nil {
		return nil, err
	}
	rules := make([]Rule, 0, len(parsed))
	for _, p := range parsed {
		rules = append(rules, p.Rule)
	}
	return rules, nil
}

// ParseToParsedRules builds the ordered rule list, user rules first so they take
// precedence over the built-in set.
func ParseToParsedRules(name string, extraRules []string) ([]ParsedRule, error) {
	return parseToParsedRules(name, extraRules, nil)
}

func parseToParsedRules(name string, extraRules []string, knownProxyIds []string) ([]ParsedRule, error) {
	var rules []ParsedRule

	builtInItems, err := readFile("rules/" + name)
	if err != nil {
		return nil, err
	}

	for _, line := range extraRules {
		rule, protocol, err := parseRawValueWithProtocol(line, knownProxyIds)
		if err == nil {
			rules = append(rules, ParsedRule{Rule: rule, Protocol: protocol})
		}
	}
	for _, line := range builtInItems {
		// Built-in sets never carry a protocol field or a named proxy.
		rule, err := ParseRawValue(line)
		if err == nil {
			rules = append(rules, ParsedRule{Rule: rule, Protocol: constants.RuleProtocolAny})
		}
	}
	return rules, nil
}

// ParseRawValue parses a three-field rule with a built-in policy.
func ParseRawValue(line string) (Rule, error) {
	rule, _, err := parseRawValueWithProtocol(line, nil)
	return rule, err
}

// ParseRawValueWithPolicies parses a rule that may name one of knownProxyIds as
// its policy, and may carry a fourth protocol field.
func ParseRawValueWithPolicies(line string, knownProxyIds []string) (Rule, constants.RuleProtocol, error) {
	return parseRawValueWithProtocol(line, knownProxyIds)
}

// parseRawValueWithProtocol accepts:
//
//	TYPE,VALUE,POLICY
//	TYPE,VALUE,POLICY,PROTOCOL
//
// POLICY is DIRECT, REJECT, PROXY, or the id of a proxy listed in
// knownProxyIds. PROTOCOL is tcp or udp.
func parseRawValueWithProtocol(line string, knownProxyIds []string) (Rule, constants.RuleProtocol, error) {
	chunks := trimArr(strings.Split(strings.TrimSpace(line), ","))

	// A DNS-MAP payload embeds its own separator, so the value chunk is not
	// necessarily free of punctuation, but the field count is still fixed.
	switch len(chunks) {
	case 3:
		rule, err := parseItem(chunks[0], chunks[1], chunks[2], knownProxyIds)
		return rule, constants.RuleProtocolAny, err
	case 4:
		protocol := constants.ParseRuleProtocol(chunks[3])
		if protocol == constants.RuleProtocolAny {
			return nil, constants.RuleProtocolAny,
				fmt.Errorf("unknown protocol %q in rule %q", chunks[3], line)
		}
		rule, err := parseItem(chunks[0], chunks[1], chunks[2], knownProxyIds)
		return rule, protocol, err
	default:
		return nil, constants.RuleProtocolAny, fmt.Errorf("invalid rule line: %q", line)
	}
}

func ParseItem(rawRuleType, value, rawPolicy string) (Rule, error) {
	return parseItem(rawRuleType, value, rawPolicy, nil)
}

// ParseItemWithPolicies is ParseItem allowing a named proxy as the policy.
func ParseItemWithPolicies(rawRuleType, value, rawPolicy string, knownProxyIds []string) (Rule, error) {
	return parseItem(rawRuleType, value, rawPolicy, knownProxyIds)
}

func parseItem(rawRuleType, value, rawPolicy string, knownProxyIds []string) (Rule, error) {
	ruleType := constants.RuleType(rawRuleType)
	policy := constants.Policy(rawPolicy)

	// A policy is valid when it is built in, or when it names a proxy the caller
	// declared. Rejecting an unknown name rather than defaulting is deliberate:
	// a rule whose target no longer exists must not quietly route somewhere
	// else, which is what silently happened when a referenced proxy was deleted.
	if !constants.IsBuiltInPolicy(policy) {
		if !slices.Contains(knownProxyIds, rawPolicy) {
			return nil, fmt.Errorf("unknown policy %q", rawPolicy)
		}
	}

	var rule Rule
	var err error

	switch ruleType {
	case constants.RuleIpCidr:
		rule, err = NewIpCidrRule(value, policy)
	case constants.RuleDomain,
		constants.RuleDomainKeyword,
		constants.RuleDomainSuffix,
		constants.RuleDomainRegex:
		rule, err = NewDomainRule(ruleType, value, policy)
	case constants.RuleProcess:
		rule, err = NewProcessRule(ruleType, value, policy)
	case constants.RuleDnsMap:
		rule, err = NewDnsMapRule(value, policy)
	default:
		err = fmt.Errorf("rule type not match: %v", ruleType)
	}
	return rule, err
}

func readFile(path string) ([]string, error) {
	file, err := data.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(file fs.File) {
		err := file.Close()
		if err != nil {
			log.Warnln(log.FormatLog(log.ConfigurationPrefix, "fail to close geo file: %v"), path)
		}
	}(file)
	items, err := list.ParseFile(file)
	if err != nil {
		return nil, err
	}
	return items, nil
}
