package constants

// Policy is the routing outcome of a rule.
//
// The three constants below are built in. A Policy may also carry the id of a
// specific proxy profile, which is how per-proxy routing works: a rule can send
// traffic to one named proxy rather than whichever proxy is currently selected.
// Such a Policy is the proxy's id verbatim, so it is compared by value like any
// other Policy and needs no separate lookup path.
type Policy string

const (
	PolicyDirect Policy = "DIRECT"
	PolicyProxy  Policy = "PROXY"
	PolicyReject Policy = "REJECT"
)

// IsBuiltInPolicy reports whether p is one of the three built-in outcomes.
// Anything else is treated as a proxy id.
func IsBuiltInPolicy(p Policy) bool {
	return p == PolicyDirect || p == PolicyProxy || p == PolicyReject
}

// RuleProtocol restricts a rule to one transport, or to neither.
//
// A rule with RuleProtocolAny is evaluated for every connection, which is the
// behaviour of a rule written without a protocol field.
type RuleProtocol string

const (
	RuleProtocolAny RuleProtocol = ""
	RuleProtocolTCP RuleProtocol = "tcp"
	RuleProtocolUDP RuleProtocol = "udp"
)

// ParseRuleProtocol maps a raw protocol field onto a RuleProtocol.
// Unrecognised input yields RuleProtocolAny so an unknown value widens the
// rule rather than silently disabling it.
func ParseRuleProtocol(s string) RuleProtocol {
	switch s {
	case "tcp", "TCP":
		return RuleProtocolTCP
	case "udp", "UDP":
		return RuleProtocolUDP
	default:
		return RuleProtocolAny
	}
}

type RuleType string

const (
	RuleIpCidr        RuleType = "IP-CIDR"
	RuleDomain        RuleType = "DOMAIN"
	RuleDomainKeyword RuleType = "DOMAIN-KEYWORD"
	RuleDomainRegex   RuleType = "DOMAIN-REGEX"
	RuleDomainSuffix  RuleType = "DOMAIN-SUFFIX"
	RuleProcess       RuleType = "PROCESS"
	RuleDnsMap        RuleType = "DNS-MAP"
	RuleBuiltIn       RuleType = "BUILT-IN"
)

var (
	IpRuleTypes      = []RuleType{RuleIpCidr}
	DomainRuleTypes  = []RuleType{RuleDomain, RuleDomainSuffix, RuleDomainRegex, RuleDomainKeyword, RuleDnsMap}
	ProcessRuleTypes = []RuleType{RuleProcess}
)

const DnsPort = "53"

func TunName() string {
	return "utun"
}

const (
	TunGateway  = "10.255.0.1/30"
	TunMtu      = 1500
	HijackedDns = "10.255.0.2"
)

const (
	DbFileName = "config.json"
)

var (
	Version   = "undefined"
	BuildTime = "undefined"
)

var FakeIpRange = "198.18.0.1/16"
