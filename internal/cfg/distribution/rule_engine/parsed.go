package rule_engine

// Protocol-aware rule wrapping.
//
// A Rule matches a value; it carries no notion of transport. Restricting a rule
// to TCP or UDP therefore cannot live on the rule itself without changing every
// implementation, so it is attached alongside as a ParsedRule and applied by the
// engine before the rule's own match condition is consulted.

import (
	"github.com/igoogolx/itun2socks/internal/constants"
)

// ParsedRule pairs a rule with the transport it applies to.
type ParsedRule struct {
	Rule     Rule
	Protocol constants.RuleProtocol
}

// appliesTo reports whether this rule should be considered for a connection on
// the given protocol.
//
// A rule with RuleProtocolAny applies to everything, which is the behaviour of a
// rule written without a protocol field. A protocol-scoped rule is skipped when
// the connection's protocol is known and differs. When the connection's protocol
// is unknown — the DNS resolver matches rules without one — a protocol-scoped
// rule is also skipped, because there is no evidence it applies and silently
// widening it would route traffic the user restricted.
func (p ParsedRule) appliesTo(protocol constants.RuleProtocol) bool {
	if p.Protocol == constants.RuleProtocolAny {
		return true
	}
	return p.Protocol == protocol
}
