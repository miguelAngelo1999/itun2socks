package constants

// RuleProtocol represents the optional protocol filter for a routing rule.
// A rule with RuleProtocolAny (the default) matches both TCP and UDP connections.
type RuleProtocol int

const (
	// RuleProtocolAny matches both TCP and UDP connections (backward-compatible default).
	RuleProtocolAny RuleProtocol = iota
	// RuleProtocolTCP restricts the rule to TCP connections only.
	RuleProtocolTCP
	// RuleProtocolUDP restricts the rule to UDP connections only.
	RuleProtocolUDP
)

// String returns the lowercase string representation of the protocol.
// Returns an empty string for RuleProtocolAny (no 4th field in rule string).
func (p RuleProtocol) String() string {
	switch p {
	case RuleProtocolTCP:
		return "tcp"
	case RuleProtocolUDP:
		return "udp"
	default:
		return ""
	}
}
