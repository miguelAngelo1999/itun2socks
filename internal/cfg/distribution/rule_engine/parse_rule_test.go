package rule_engine

import (
	"testing"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ParseRawValueWithProtocol — unit tests for task 1.3
// Covers: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8
// ---------------------------------------------------------------------------

// Requirement 1.1 — 3-field rule defaults to RuleProtocolAny
func TestParseRawValueWithProtocol_ThreeFields_DefaultsToAny(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DOMAIN,example.com,DIRECT")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleProtocolAny, rule.Protocol)
}

// Requirement 1.2 — 4th field "tcp" (lowercase) maps to RuleProtocolTCP
func TestParseRawValueWithProtocol_TcpLowercase(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DOMAIN,example.com,DIRECT,tcp")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleProtocolTCP, rule.Protocol)
}

// Requirement 1.2 — 4th field "TCP" (uppercase) also maps to RuleProtocolTCP
func TestParseRawValueWithProtocol_TcpUppercase(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DOMAIN,example.com,DIRECT,TCP")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleProtocolTCP, rule.Protocol)
}

// Requirement 1.2 — 4th field "Tcp" (mixed case) also maps to RuleProtocolTCP
func TestParseRawValueWithProtocol_TcpMixedCase(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DOMAIN-SUFFIX,whatsapp.net,PROXY,Tcp")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleProtocolTCP, rule.Protocol)
}

// Requirement 1.3 — 4th field "udp" maps to RuleProtocolUDP
func TestParseRawValueWithProtocol_UdpLowercase(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DOMAIN-SUFFIX,whatsapp.net,DIRECT,udp")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleProtocolUDP, rule.Protocol)
}

// Requirement 1.3 — 4th field "UDP" (uppercase) also maps to RuleProtocolUDP
func TestParseRawValueWithProtocol_UdpUppercase(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DOMAIN-SUFFIX,signal.org,DIRECT,UDP")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleProtocolUDP, rule.Protocol)
}

// Requirement 1.4 — invalid 4th field returns error and is skipped
func TestParseRawValueWithProtocol_InvalidProtocol_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("DOMAIN,example.com,DIRECT,quic")
	assert.Error(t, err)
}

func TestParseRawValueWithProtocol_InvalidProtocol_Icmp(t *testing.T) {
	_, err := ParseRawValueWithProtocol("DOMAIN,example.com,DIRECT,icmp")
	assert.Error(t, err)
}

// Requirement 1.5 — fewer than 3 fields is invalid
func TestParseRawValueWithProtocol_TwoFields_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("DOMAIN,example.com")
	assert.Error(t, err)
}

func TestParseRawValueWithProtocol_OneField_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("DOMAIN")
	assert.Error(t, err)
}

// Requirement 1.6 — rules prefixed with # are skipped
func TestParseRawValueWithProtocol_CommentedRule_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("#DOMAIN,example.com,DIRECT")
	assert.Error(t, err)
}

func TestParseRawValueWithProtocol_CommentedRule_WithProtocol_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("#DOMAIN,example.com,DIRECT,tcp")
	assert.Error(t, err)
}

// Requirement 1.7 — empty/whitespace-only rules are skipped
func TestParseRawValueWithProtocol_EmptyString_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("")
	assert.Error(t, err)
}

func TestParseRawValueWithProtocol_WhitespaceOnly_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("   ")
	assert.Error(t, err)
}

// Requirement 1.8 — ruleType is normalised to uppercase
func TestParseRawValueWithProtocol_LowercaseRuleType_NormalisedToUpper(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("domain,example.com,DIRECT")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleDomain, rule.Type())
}

func TestParseRawValueWithProtocol_MixedCaseRuleType_NormalisedToUpper(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("Domain-Suffix,example.com,DIRECT")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleDomainSuffix, rule.Type())
}

// Action, match, and rule type fields are correctly populated
func TestParseRawValueWithProtocol_FieldsPopulatedCorrectly(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DOMAIN-SUFFIX,example.com,PROXY,tcp")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleDomainSuffix, rule.Type())
	assert.Equal(t, "example.com", rule.Value())
	assert.Equal(t, constants.PolicyProxy, rule.GetPolicy())
	assert.Equal(t, constants.RuleProtocolTCP, rule.Protocol)
}

// Whitespace around fields should be trimmed
func TestParseRawValueWithProtocol_WhitespacePaddedFields(t *testing.T) {
	rule, err := ParseRawValueWithProtocol(" DOMAIN , example.com , DIRECT , udp ")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleDomain, rule.Type())
	assert.Equal(t, "example.com", rule.Value())
	assert.Equal(t, constants.PolicyDirect, rule.GetPolicy())
	assert.Equal(t, constants.RuleProtocolUDP, rule.Protocol)
}

// Named proxy (non-standard policy) should be accepted
func TestParseRawValueWithProtocol_NamedProxy_Accepted(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DOMAIN-SUFFIX,whatsapp.net,LP,udp")
	require.NoError(t, err)
	assert.Equal(t, constants.Policy("LP"), rule.GetPolicy())
	assert.Equal(t, constants.RuleProtocolUDP, rule.Protocol)
}

// IP-CIDR rule with tcp protocol
func TestParseRawValueWithProtocol_IpCidr_WithTcp(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("IP-CIDR,192.168.0.0/24,DIRECT,tcp")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleIpCidr, rule.Type())
	assert.Equal(t, constants.RuleProtocolTCP, rule.Protocol)
}

// -------------------------------------------------------------------------
// DST-PORT validation — unit tests for task 1.5
// Covers: Requirements 2.1, 2.2, 2.3
// -------------------------------------------------------------------------

// Requirement 2.1 — valid DST-PORT rule (port in range 1–65535) produces a ParsedRule
func TestParseRawValueWithProtocol_DstPort_ValidPort_Produces_ParsedRule(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DST-PORT,993,DIRECT")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleDstPort, rule.Type())
	assert.Equal(t, "993", rule.Value())
	assert.Equal(t, constants.PolicyDirect, rule.GetPolicy())
	assert.Equal(t, constants.RuleProtocolAny, rule.Protocol)
}

// Requirement 2.1 — valid DST-PORT rule with protocol field
func TestParseRawValueWithProtocol_DstPort_ValidPort_WithProtocol(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DST-PORT,5060,DIRECT,udp")
	require.NoError(t, err)
	assert.Equal(t, constants.RuleDstPort, rule.Type())
	assert.Equal(t, "5060", rule.Value())
	assert.Equal(t, constants.RuleProtocolUDP, rule.Protocol)
}

// Requirement 2.1 — boundary: port 1 (minimum valid)
func TestParseRawValueWithProtocol_DstPort_Port1_Valid(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DST-PORT,1,PROXY")
	require.NoError(t, err)
	assert.Equal(t, "1", rule.Value())
}

// Requirement 2.1 — boundary: port 65535 (maximum valid)
func TestParseRawValueWithProtocol_DstPort_Port65535_Valid(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DST-PORT,65535,PROXY")
	require.NoError(t, err)
	assert.Equal(t, "65535", rule.Value())
}

// Requirement 2.2 — non-numeric match field returns error
func TestParseRawValueWithProtocol_DstPort_NonNumeric_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("DST-PORT,abc,DIRECT")
	assert.Error(t, err)
}

// Requirement 2.2 — empty match field returns error
func TestParseRawValueWithProtocol_DstPort_EmptyMatch_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("DST-PORT,,DIRECT")
	assert.Error(t, err)
}

// Requirement 2.2 — float match field returns error (not a valid integer)
func TestParseRawValueWithProtocol_DstPort_FloatMatch_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("DST-PORT,80.5,DIRECT")
	assert.Error(t, err)
}

// Requirement 2.3 — port 0 (below range) returns error
func TestParseRawValueWithProtocol_DstPort_Port0_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("DST-PORT,0,DIRECT")
	assert.Error(t, err)
}

// Requirement 2.3 — port 65536 (above range) returns error
func TestParseRawValueWithProtocol_DstPort_Port65536_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("DST-PORT,65536,DIRECT")
	assert.Error(t, err)
}

// Requirement 2.3 — large negative port returns error
func TestParseRawValueWithProtocol_DstPort_NegativePort_ReturnsError(t *testing.T) {
	_, err := ParseRawValueWithProtocol("DST-PORT,-1,DIRECT")
	assert.Error(t, err)
}

// Requirement 2.1 — named proxy action accepted for DST-PORT
func TestParseRawValueWithProtocol_DstPort_NamedProxy_Accepted(t *testing.T) {
	rule, err := ParseRawValueWithProtocol("DST-PORT,993,LP")
	require.NoError(t, err)
	assert.Equal(t, constants.Policy("LP"), rule.GetPolicy())
	assert.Equal(t, "993", rule.Value())
}
