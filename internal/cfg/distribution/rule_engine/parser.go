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

// ParseToParsedRules builds the ordered []ParsedRule list used by Engine.
// Extra (customized) rules are prepended so they take priority over
// built-in rules, preserving first-match-wins semantics (Req 4.1, 4.4).
// Each rule is parsed via ParseRawValueWithProtocol so the optional
// protocol field (4th comma field) is captured (Req 1.1-1.4).
// Invalid rules are silently skipped with a logged warning (Req 6.1, 6.2).
func ParseToParsedRules(name string, extraRules []string) ([]ParsedRule, error) {
var rules []ParsedRule
builtInItems, err := readFile("rules/" + name)
if err != nil {
return nil, err
}
for _, line := range extraRules {
parsed, err := ParseRawValueWithProtocol(line)
if err == nil {
rules = append(rules, parsed)
}
}
for _, line := range builtInItems {
parsed, err := ParseRawValueWithProtocol(line)
if err == nil {
rules = append(rules, parsed)
}
}
return rules, nil
}

// Parse retains backward compatibility for callers that only need []Rule
// (e.g. configuration.GetBuiltInRules used for display/validation).
// It wraps ParseToParsedRules and strips the protocol wrapper.
func Parse(name string, extraRules []string) ([]Rule, error) {
parsed, err := ParseToParsedRules(name, extraRules)
if err != nil {
return nil, err
}
var rules []Rule
for _, p := range parsed {
rules = append(rules, p.Rule)
}
return rules, nil
}

func ParseRawValue(line string) (Rule, error) {
chunks := trimArr(strings.Split(strings.TrimSpace(line), ","))
// Allow 3-field (TYPE,MATCH,ACTION) and 4-field (TYPE,MATCH,ACTION,PROTOCOL) rules.
// The optional 4th protocol field is validated but not used here — it is stored as-is.
if len(chunks) < 3 || len(chunks) > 4 {
return nil, fmt.Errorf("invald rule line")
}
if len(chunks) == 4 {
proto := strings.ToLower(chunks[3])
if proto != "tcp" && proto != "udp" {
return nil, fmt.Errorf("invalid protocol field %q: must be tcp or udp", chunks[3])
}
}
return ParseItem(chunks[0], chunks[1], chunks[2])

}

func ParseItem(rawRuleType, value, rawPolicy string) (Rule, error) {
ruleType := constants.RuleType(rawRuleType)

var rule Rule
var err error
policy := constants.Policy(rawPolicy)
// Allow standard policies AND named proxy IDs for per-profile routing
isStandardPolicy := slices.Contains([]constants.Policy{constants.PolicyDirect, constants.PolicyReject, constants.PolicyProxy}, policy)
if !isStandardPolicy && rawPolicy == "" {
return nil, fmt.Errorf("policy not match: %v", ruleType)
}

switch ruleType {
case constants.RuleIpCidr:
rule, err = NewIpCidrRule(value, policy)
break
case constants.RuleDomain:
rule, err = NewDomainRule(ruleType, value, policy)
break
case constants.RuleDomainKeyword:
rule, err = NewDomainRule(ruleType, value, policy)
break
case constants.RuleDomainSuffix:
rule, err = NewDomainRule(ruleType, value, policy)
break
case constants.RuleDomainRegex:
rule, err = NewDomainRule(ruleType, value, policy)
break
case constants.RuleProcess:
rule, err = NewProcessRule(ruleType, value, policy)
break
case constants.RuleDnsMap:
rule, err = NewDnsMapRule(value, policy)
break
case constants.RuleDstPort:
rule, err = NewDstPortRule(value, policy)
break
case constants.RuleUrlPath:
rule, err = NewUrlPathRule(value, policy)
break
case constants.RuleUrlRegex:
rule, err = NewUrlRegexRule(value, policy)
break
case constants.RuleHeader:
rule, err = NewHeaderRule(value, policy)
break
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
return items, nil
}
