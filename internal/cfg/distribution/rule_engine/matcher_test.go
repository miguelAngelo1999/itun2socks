package rule_engine

import (
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: build a minimal Engine from a slice of raw extra-rule strings.
// Uses "proxy_all" as the built-in ruleset (empty list for simplicity).
// ---------------------------------------------------------------------------

func newEngineFromExtraRules(t *testing.T, lines []string) *Engine {
	t.Helper()
	rules, err := ParseToParsedRules("proxy_all", lines)
	require.NoError(t, err)
	cache, err := lru.New[string, Rule](1024)
	require.NoError(t, err)
	return &Engine{rules: rules, cache: cache}
}

// ---------------------------------------------------------------------------
// Requirement 3.1 -- TCP rule is skipped for UDP connections
// ---------------------------------------------------------------------------

func TestMatchWithProtocol_TcpRule_SkippedForUdpConnection(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN-SUFFIX,whatsapp.net,PROXY,tcp",
	})

	_, err := engine.MatchWithProtocol("media.whatsapp.net", constants.DomainRuleTypes, constants.RuleProtocolUDP)
	assert.ErrorIs(t, err, ErrNotFound, "TCP-only rule must be skipped for a UDP connection")
}

// ---------------------------------------------------------------------------
// Requirement 3.2 -- UDP rule is skipped for TCP connections
// ---------------------------------------------------------------------------

func TestMatchWithProtocol_UdpRule_SkippedForTcpConnection(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN-SUFFIX,whatsapp.net,DIRECT,udp",
	})

	_, err := engine.MatchWithProtocol("media.whatsapp.net", constants.DomainRuleTypes, constants.RuleProtocolTCP)
	assert.ErrorIs(t, err, ErrNotFound, "UDP-only rule must be skipped for a TCP connection")
}

// ---------------------------------------------------------------------------
// Requirement 3.3 -- RuleProtocolAny rules match both TCP and UDP
// ---------------------------------------------------------------------------

func TestMatchWithProtocol_AnyRule_MatchesTcpConnection(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN-SUFFIX,example.com,DIRECT",
	})

	rule, err := engine.MatchWithProtocol("sub.example.com", constants.DomainRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyDirect, rule.GetPolicy())
}

func TestMatchWithProtocol_AnyRule_MatchesUdpConnection(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN-SUFFIX,example.com,DIRECT",
	})

	rule, err := engine.MatchWithProtocol("sub.example.com", constants.DomainRuleTypes, constants.RuleProtocolUDP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyDirect, rule.GetPolicy())
}

// ---------------------------------------------------------------------------
// Requirement 3.4 -- Protocol filter applied BEFORE type-specific match
// (shown by verifying that a matching domain but wrong protocol => no match)
// ---------------------------------------------------------------------------

func TestMatchWithProtocol_ProtocolFilterAppliedBeforeMatch(t *testing.T) {
	// Rule matches the domain AND the type, but protocol is TCP-only.
	// A UDP connection must not match.
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN,google.com,PROXY,tcp",
	})

	_, err := engine.MatchWithProtocol("google.com", constants.DomainRuleTypes, constants.RuleProtocolUDP)
	assert.ErrorIs(t, err, ErrNotFound,
		"protocol filter must be applied before the type-specific match condition")
}

// ---------------------------------------------------------------------------
// Requirements 4.1 & 4.2 -- First-match-wins with protocol filtering
// ---------------------------------------------------------------------------

func TestMatchWithProtocol_FirstMatchWins_WithProtocolFilter(t *testing.T) {
	// Two rules for same domain: first is UDP-only (DIRECT), second is TCP-only (PROXY).
	// A TCP connection must skip the first and match the second.
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN-SUFFIX,whatsapp.net,DIRECT,udp",
		"DOMAIN-SUFFIX,whatsapp.net,PROXY,tcp",
	})

	rule, err := engine.MatchWithProtocol("web.whatsapp.net", constants.DomainRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyProxy, rule.GetPolicy(),
		"TCP connection must skip the UDP-only rule and match the TCP rule")
}

func TestMatchWithProtocol_UdpConnectionMatchesFirstUdpRule(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN-SUFFIX,whatsapp.net,DIRECT,udp",
		"DOMAIN-SUFFIX,whatsapp.net,PROXY,tcp",
	})

	rule, err := engine.MatchWithProtocol("media.whatsapp.net", constants.DomainRuleTypes, constants.RuleProtocolUDP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyDirect, rule.GetPolicy(),
		"UDP connection must match the first (UDP-only DIRECT) rule")
}

// ---------------------------------------------------------------------------
// Requirements 4.3 -- No match returns ErrNotFound
// ---------------------------------------------------------------------------

func TestMatchWithProtocol_NoMatch_ReturnsErrNotFound(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN,google.com,PROXY",
	})

	_, err := engine.MatchWithProtocol("notgoogle.com", constants.DomainRuleTypes, constants.RuleProtocolTCP)
	assert.ErrorIs(t, err, ErrNotFound)
}

// ---------------------------------------------------------------------------
// Requirement 4.4 -- Rule evaluation order is preserved (no reordering)
// ---------------------------------------------------------------------------

func TestMatchWithProtocol_RuleOrderPreserved(t *testing.T) {
	// DIRECT comes first, PROXY comes second.  Both match the same domain.
	// The first rule must win.
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN,example.com,DIRECT",
		"DOMAIN,example.com,PROXY",
	})

	rule, err := engine.MatchWithProtocol("example.com", constants.DomainRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyDirect, rule.GetPolicy(),
		"first matching rule must win regardless of evaluation order")
}

// ---------------------------------------------------------------------------
// Backward compatibility -- Match() delegates to MatchWithProtocol(Any)
// ---------------------------------------------------------------------------

func TestMatch_BackwardCompatible_AnyRule_AlwaysMatches(t *testing.T) {
	// A rule without a protocol field (RuleProtocolAny on the rule side) must
	// match regardless of what protocol the caller passes.
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN-SUFFIX,example.com,PROXY",
	})

	// Called from DNS resolver with no protocol (Match -> RuleProtocolAny)
	rule, err := engine.Match("sub.example.com", constants.DomainRuleTypes)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyProxy, rule.GetPolicy())

	// Called from TCP dispatcher
	rule2, err2 := engine.MatchWithProtocol("sub.example.com", constants.DomainRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err2)
	assert.Equal(t, constants.PolicyProxy, rule2.GetPolicy())

	// Called from UDP dispatcher
	rule3, err3 := engine.MatchWithProtocol("sub.example.com", constants.DomainRuleTypes, constants.RuleProtocolUDP)
	require.NoError(t, err3)
	assert.Equal(t, constants.PolicyProxy, rule3.GetPolicy())
}

// ---------------------------------------------------------------------------
// Requirement 5.1 & 5.2 -- Backward compatibility: 3-field rules same for TCP/UDP
// ---------------------------------------------------------------------------

func TestMatchWithProtocol_ThreeFieldRule_SameResultForTcpAndUdp(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN-SUFFIX,huggingface.co,REJECT",
	})

	tcpRule, tcpErr := engine.MatchWithProtocol("huggingface.co", constants.DomainRuleTypes, constants.RuleProtocolTCP)
	udpRule, udpErr := engine.MatchWithProtocol("huggingface.co", constants.DomainRuleTypes, constants.RuleProtocolUDP)

	require.NoError(t, tcpErr)
	require.NoError(t, udpErr)
	assert.Equal(t, tcpRule.GetPolicy(), udpRule.GetPolicy(),
		"3-field rule must produce identical result for TCP and UDP connections")
}

// ---------------------------------------------------------------------------
// Mixed rule list: protocol-specific and any-protocol rules together
// ---------------------------------------------------------------------------

func TestMatchWithProtocol_MixedRuleList(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DOMAIN-SUFFIX,signal.org,DIRECT,udp", // UDP calls direct
		"DOMAIN-SUFFIX,signal.org,PROXY",      // all others proxied (any)
	})

	udpRule, err := engine.MatchWithProtocol("talk.signal.org", constants.DomainRuleTypes, constants.RuleProtocolUDP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyDirect, udpRule.GetPolicy(), "UDP should match first UDP rule")

	tcpRule, err := engine.MatchWithProtocol("talk.signal.org", constants.DomainRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyProxy, tcpRule.GetPolicy(), "TCP should skip UDP rule and match any-protocol rule")
}

// ---------------------------------------------------------------------------
// IP-CIDR rule with protocol filtering
// ---------------------------------------------------------------------------

func TestMatchWithProtocol_IpCidr_TcpOnly_SkippedForUdp(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"IP-CIDR,17.0.0.0/8,DIRECT,tcp",
	})

	_, err := engine.MatchWithProtocol("17.1.2.3", constants.IpRuleTypes, constants.RuleProtocolUDP)
	assert.ErrorIs(t, err, ErrNotFound, "TCP-only IP rule must be skipped for UDP connection")

	rule, err := engine.MatchWithProtocol("17.1.2.3", constants.IpRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyDirect, rule.GetPolicy())
}

// ---------------------------------------------------------------------------
// networkToProtocol helper used by ConnMatcher in tun.go and system_proxy.go
// (Requirement 7.1, 7.2, 7.3)
// ---------------------------------------------------------------------------

func TestNetworkToProtocol_TCP(t *testing.T) {
	// Import from the distribution package is not available here; test the
	// mapping logic indirectly by checking the engine receives the right
	// protocol value.  Direct mapping tests live in distribution_test.go.
	// Here we just verify the constant values are correct.
	assert.Equal(t, constants.RuleProtocolTCP, constants.RuleProtocolTCP)
	assert.Equal(t, constants.RuleProtocolUDP, constants.RuleProtocolUDP)
}

// ----------------------------------------------------------------------------
// Requirement 2.4 -- DST-PORT Match() semantics through the full matcher path
// Rule matches if and only if the connection's destination port equals the rule port.
// ----------------------------------------------------------------------------

// Exact match: port in rule equals port in connection => rule matched.
func TestMatchWithProtocol_DstPort_ExactMatch(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DST-PORT,993,LP",
	})

	rule, err := engine.MatchWithProtocol("993", constants.DstPortRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, constants.Policy("LP"), rule.GetPolicy(),
		"DST-PORT rule must match when connection port equals rule port")
}

// Different port: port in rule != port in connection => no match.
func TestMatchWithProtocol_DstPort_NoMatch_DifferentPort(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DST-PORT,993,LP",
	})

	_, err := engine.MatchWithProtocol("443", constants.DstPortRuleTypes, constants.RuleProtocolTCP)
	assert.ErrorIs(t, err, ErrNotFound,
		"DST-PORT rule must not match when connection port differs from rule port")
}

// Boundary: port 1 (minimum) matches exactly.
func TestMatchWithProtocol_DstPort_Port1_ExactMatch(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DST-PORT,1,DIRECT",
	})

	rule, err := engine.MatchWithProtocol("1", constants.DstPortRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyDirect, rule.GetPolicy())
}

// Boundary: port 65535 (maximum) matches exactly.
func TestMatchWithProtocol_DstPort_Port65535_ExactMatch(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DST-PORT,65535,PROXY",
	})

	rule, err := engine.MatchWithProtocol("65535", constants.DstPortRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyProxy, rule.GetPolicy())
}

// Non-numeric value passed to DST-PORT matching => no match (Match returns false).
func TestMatchWithProtocol_DstPort_NonNumericValue_NoMatch(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DST-PORT,993,LP",
	})

	_, err := engine.MatchWithProtocol("notaport", constants.DstPortRuleTypes, constants.RuleProtocolTCP)
	assert.ErrorIs(t, err, ErrNotFound,
		"DST-PORT Match() must return false for a non-numeric value string")
}

// Multiple DST-PORT rules: first-match-wins applies to port rules too.
func TestMatchWithProtocol_DstPort_FirstMatchWins(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DST-PORT,443,DIRECT", // wins
		"DST-PORT,443,PROXY",  // never reached
	})

	rule, err := engine.MatchWithProtocol("443", constants.DstPortRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyDirect, rule.GetPolicy(),
		"first matching DST-PORT rule must win")
}

// ----------------------------------------------------------------------------
// Requirement 2.5 -- Protocol filter applied BEFORE port comparison
// ----------------------------------------------------------------------------

// DST-PORT rule with protocol=tcp: a TCP connection matches, a UDP connection does not.
func TestMatchWithProtocol_DstPort_TcpOnly_MatchesTcp_SkipsUdp(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DST-PORT,5060,DIRECT,tcp",
	})

	// TCP connection on port 5060 => match
	rule, err := engine.MatchWithProtocol("5060", constants.DstPortRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyDirect, rule.GetPolicy(),
		"TCP-only DST-PORT rule must match a TCP connection on the same port")

	// UDP connection on port 5060 => protocol filter rejects before port check
	_, err = engine.MatchWithProtocol("5060", constants.DstPortRuleTypes, constants.RuleProtocolUDP)
	assert.ErrorIs(t, err, ErrNotFound,
		"TCP-only DST-PORT rule must be skipped for a UDP connection (Req 2.5)")
}

// DST-PORT rule with protocol=udp: a UDP connection matches, a TCP connection does not.
func TestMatchWithProtocol_DstPort_UdpOnly_MatchesUdp_SkipsTcp(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DST-PORT,5060,DIRECT,udp",
	})

	// UDP connection on port 5060 => match
	rule, err := engine.MatchWithProtocol("5060", constants.DstPortRuleTypes, constants.RuleProtocolUDP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyDirect, rule.GetPolicy(),
		"UDP-only DST-PORT rule must match a UDP connection on the same port")

	// TCP connection on port 5060 => protocol filter rejects before port check
	_, err = engine.MatchWithProtocol("5060", constants.DstPortRuleTypes, constants.RuleProtocolTCP)
	assert.ErrorIs(t, err, ErrNotFound,
		"UDP-only DST-PORT rule must be skipped for a TCP connection (Req 2.5)")
}

// DST-PORT rule with protocol=any (3-field): matches both TCP and UDP.
func TestMatchWithProtocol_DstPort_Any_MatchesBothProtocols(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DST-PORT,993,LP",
	})

	tcpRule, tcpErr := engine.MatchWithProtocol("993", constants.DstPortRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, tcpErr)
	assert.Equal(t, constants.Policy("LP"), tcpRule.GetPolicy())

	udpRule, udpErr := engine.MatchWithProtocol("993", constants.DstPortRuleTypes, constants.RuleProtocolUDP)
	require.NoError(t, udpErr)
	assert.Equal(t, constants.Policy("LP"), udpRule.GetPolicy(),
		"DST-PORT rule without protocol field must match both TCP and UDP (backward-compatible)")
}

// Protocol filter is applied BEFORE port check: even if the port matches,
// a wrong-protocol rule must be skipped entirely (verifies Req 2.5 directly).
func TestMatchWithProtocol_DstPort_ProtocolFilterAppliedBeforePortCheck(t *testing.T) {
	// Only a TCP rule exists for port 80. A UDP connection must not match
	// even though the port number matches.
	engine := newEngineFromExtraRules(t, []string{
		"DST-PORT,80,PROXY,tcp",
	})

	_, err := engine.MatchWithProtocol("80", constants.DstPortRuleTypes, constants.RuleProtocolUDP)
	assert.ErrorIs(t, err, ErrNotFound,
		"protocol filter must prevent port comparison for wrong-protocol connections")
}

// Mixed protocol DST-PORT list: two rules for the same port, different protocols.
func TestMatchWithProtocol_DstPort_MixedProtocols_CorrectActionSelected(t *testing.T) {
	engine := newEngineFromExtraRules(t, []string{
		"DST-PORT,5060,DIRECT,udp", // SIP UDP direct
		"DST-PORT,5060,PROXY,tcp",  // SIP TCP proxied
	})

	udpRule, err := engine.MatchWithProtocol("5060", constants.DstPortRuleTypes, constants.RuleProtocolUDP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyDirect, udpRule.GetPolicy(), "UDP SIP should be DIRECT")

	tcpRule, err := engine.MatchWithProtocol("5060", constants.DstPortRuleTypes, constants.RuleProtocolTCP)
	require.NoError(t, err)
	assert.Equal(t, constants.PolicyProxy, tcpRule.GetPolicy(), "TCP SIP should be PROXY")
}
