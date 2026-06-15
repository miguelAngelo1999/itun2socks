package rule_engine

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// ParseRawValueWithProtocol parses a raw rule string (from config.json) into
// a ParsedRule that includes the optional protocol filter field.
//
// Format: RULE-TYPE,MATCH,ACTION[,PROTOCOL]
//
// Rules:
//   - Empty or whitespace-only lines are skipped (returns error).
//   - Lines prefixed with '#' are treated as disabled and skipped (returns error).
//   - ruleType is normalised to uppercase.
//   - The optional 4th field must be "tcp" or "udp" (case-insensitive);
//     any other value causes the rule to be skipped with a logged warning.
//   - When no 4th field is present, Protocol defaults to RuleProtocolAny.
func ParseRawValueWithProtocol(line string) (ParsedRule, error) {
	trimmed := strings.TrimSpace(line)

	// Skip empty / whitespace-only lines (Requirement 1.7)
	if trimmed == "" {
		return ParsedRule{}, fmt.Errorf("empty rule line")
	}

	// Skip commented-out (disabled) rules (Requirement 1.6)
	if strings.HasPrefix(trimmed, "#") {
		return ParsedRule{}, fmt.Errorf("disabled rule (starts with '#')")
	}

	chunks := trimArr(strings.Split(trimmed, ","))

	// Require at least 3 fields: RULE-TYPE, MATCH, ACTION (Requirement 1.5)
	if len(chunks) < 3 {
		return ParsedRule{}, fmt.Errorf("invalid rule line: fewer than 3 fields: %q", trimmed)
	}

	// Normalise ruleType to uppercase (Requirement 1.8)
	rawRuleType := strings.ToUpper(chunks[0])
	value := chunks[1]
	rawPolicy := chunks[2]

	// Parse the optional 4th field as protocol (Requirements 1.1–1.4)
	protocol := constants.RuleProtocolAny
	if len(chunks) >= 4 {
		protoStr := strings.ToLower(chunks[3])
		switch protoStr {
		case "tcp":
			protocol = constants.RuleProtocolTCP
		case "udp":
			protocol = constants.RuleProtocolUDP
		default:
			log.Warnln(log.FormatLog(log.RulePrefix,
				"invalid protocol field %q in rule %q — rule skipped"), chunks[3], trimmed)
			return ParsedRule{}, fmt.Errorf("invalid protocol field %q in rule %q", chunks[3], trimmed)
		}
	}

	// Validate DST-PORT match field (Requirements 2.2, 2.3)
	if rawRuleType == string(constants.RuleDstPort) {
		port, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			log.Warnln(log.FormatLog(log.RulePrefix,
				"DST-PORT match field is not a valid integer %q in rule %q — rule skipped"), value, trimmed)
			return ParsedRule{}, fmt.Errorf("DST-PORT match field is not a valid integer %q", value)
		}
		if port < 1 || port > 65535 {
			log.Warnln(log.FormatLog(log.RulePrefix,
				"DST-PORT port %d is out of range 1–65535 in rule %q — rule skipped"), port, trimmed)
			return ParsedRule{}, fmt.Errorf("DST-PORT port %d is out of range 1–65535", port)
		}
	}

	// Build the underlying Rule using the existing ParseItem helper.
	rule, err := ParseItem(rawRuleType, value, rawPolicy)
	if err != nil {
		return ParsedRule{}, fmt.Errorf("failed to parse rule %q: %w", trimmed, err)
	}

	return NewParsedRule(rule, protocol), nil
}
