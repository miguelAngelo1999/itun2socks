package rule_engine

import (
	"github.com/igoogolx/itun2socks/internal/constants"
)

// ParsedRule wraps a Rule with an optional protocol filter.
// It represents a fully parsed rule from config.json including the optional
// 4th comma-separated field (Protocol_Field).
//
// The Protocol field defaults to RuleProtocolAny for backward compatibility:
// rules without a 4th field continue to match both TCP and UDP connections.
type ParsedRule struct {
	// Rule is the underlying typed rule (Domain, IpCidr, Process, DstPort, etc.)
	Rule
	// Protocol restricts matching to TCP-only, UDP-only, or both (any).
	// Defaults to RuleProtocolAny when no 4th field is present in the rule string.
	Protocol constants.RuleProtocol
}

// NewParsedRule wraps an existing Rule with a protocol filter.
// Pass RuleProtocolAny for rules that should match both TCP and UDP.
func NewParsedRule(rule Rule, protocol constants.RuleProtocol) ParsedRule {
	return ParsedRule{
		Rule:     rule,
		Protocol: protocol,
	}
}
