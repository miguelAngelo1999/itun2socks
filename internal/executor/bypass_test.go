package executor

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectBypassCidrs(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	content := `{
		"setting": {
			"bypassCidrs": ["10.0.0.0/8", "192.168.1.1"]
		},
		"proxy": [
			{"id": "proxy1", "server": "1.2.3.4"}
		],
		"rules": [
			"IP-CIDR,172.16.0.0/12,DIRECT",
			"IP-CIDR,8.8.8.8,PROXY",
			"DOMAIN,google.com,DIRECT"
		]
	}`
	err := os.WriteFile(cfgPath, []byte(content), 0644)
	require.NoError(t, err)

	origPath, _ := configuration.GetConfigFilePath()
	t.Cleanup(func() {
		configuration.SetConfigFilePath(origPath)
	})
	configuration.SetConfigFilePath(cfgPath)

	excludes := collectBypassCidrs()
	var actual []string
	for _, p := range excludes {
		actual = append(actual, p.String())
	}

	assert.Contains(t, actual, "10.0.0.0/8")
	assert.Contains(t, actual, "192.168.1.1/32")
	assert.Contains(t, actual, "1.2.3.4/32")
	assert.Contains(t, actual, "172.16.0.0/12")
	assert.NotContains(t, actual, "8.8.8.8/32")
	assert.NotContains(t, actual, "57.144.0.0/14")
}

func TestCollectBypassCidrs_DynamicPacUpstream(t *testing.T) {
	pac.DefaultRegistry.Clear()
	t.Cleanup(func() { pac.DefaultRegistry.Clear() })

	// Populate a PAC whose upstream is constructed dynamically in JS
	// (no literal "PROXY host:port" substring for static regex).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
function FindProxyForURL(url, host) {
    var ip = "10.99." + "88.77";
    return "PROXY " + ip + ":8082";
}`))
	}))
	defer srv.Close()

	pac.DefaultRegistry.Update([]map[string]any{
		{"id": "pac1", "server": "", "pacUrl": srv.URL},
	}, "")

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`{"setting":{},"proxy":[],"rules":[]}`), 0644))

	origPath, _ := configuration.GetConfigFilePath()
	t.Cleanup(func() { configuration.SetConfigFilePath(origPath) })
	configuration.SetConfigFilePath(cfgPath)

	excludes := collectBypassCidrs()
	var actual []string
	for _, p := range excludes {
		actual = append(actual, p.String())
	}
	assert.Contains(t, actual, "10.99.88.77/32")
}

func TestCollectBypassCidrs_ProtocolScopedAndEffectiveRules(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	content := `{
		"setting": {},
		"proxy": [],
		"ruleGroups": [
			{"id": "grp-on", "name": "Enabled Group", "enabled": true, "order": 0},
			{"id": "grp-off", "name": "Disabled Group", "enabled": false, "order": 1}
		],
		"customizedRules": [
			{
				"id": "r1",
				"groupId": "grp-on",
				"conditions": [{"type": "IP-CIDR", "value": "172.20.0.0/16"}],
				"policy": {"kind": "direct"},
				"enabled": true,
				"order": 0
			},
			{
				"id": "r2",
				"groupId": "grp-on",
				"conditions": [{"type": "IP-CIDR", "value": "57.144.0.0/14"}],
				"policy": {"kind": "direct"},
				"network": "udp",
				"enabled": true,
				"order": 1
			},
			{
				"id": "r3",
				"groupId": "grp-on",
				"conditions": [{"type": "IP-CIDR", "value": "157.240.0.0/16"}],
				"policy": {"kind": "direct"},
				"network": "tcp",
				"enabled": true,
				"order": 2
			},
			{
				"id": "r4",
				"groupId": "grp-on",
				"conditions": [{"type": "IP-CIDR", "value": "10.99.0.0/16"}],
				"policy": {"kind": "direct"},
				"enabled": false,
				"order": 3
			},
			{
				"id": "r5",
				"groupId": "grp-off",
				"conditions": [{"type": "IP-CIDR", "value": "10.88.0.0/16"}],
				"policy": {"kind": "direct"},
				"enabled": true,
				"order": 0
			},
			{
				"id": "r6",
				"groupId": "grp-on",
				"conditions": [
					{"type": "IP-CIDR", "value": "10.66.0.0/16"},
					{"type": "PROCESS", "value": "WhatsApp.Root.exe"}
				],
				"policy": {"kind": "direct"},
				"enabled": true,
				"order": 4
			}
		],
		"rules": [
			"IP-CIDR,10.77.0.0/16,DIRECT"
		]
	}`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))

	origPath, _ := configuration.GetConfigFilePath()
	t.Cleanup(func() { configuration.SetConfigFilePath(origPath) })
	configuration.SetConfigFilePath(cfgPath)

	excludes := collectBypassCidrs()
	var actual []string
	for _, p := range excludes {
		actual = append(actual, p.String())
	}

	assert.Contains(t, actual, "172.20.0.0/16")
	assert.NotContains(t, actual, "57.144.0.0/14", "UDP-scoped IP-CIDR must not become L3 route exclude")
	assert.NotContains(t, actual, "157.240.0.0/16", "TCP-scoped IP-CIDR must not become L3 route exclude")
	assert.NotContains(t, actual, "10.99.0.0/16", "disabled rule must be excluded")
	assert.NotContains(t, actual, "10.88.0.0/16", "rule in disabled group must be excluded")
	assert.NotContains(t, actual, "10.66.0.0/16", "compound rule must not be over-broadened at L3")
	assert.NotContains(t, actual, "10.77.0.0/16", "legacy rules shadow must be ignored when customizedRules is populated")
}

func TestCollectBypassCidrs_LegacyProtocolScopedSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	content := `{
		"setting": {},
		"proxy": [],
		"rules": [
			"IP-CIDR,172.16.0.0/12,DIRECT",
			"IP-CIDR,57.144.0.0/14,DIRECT,udp",
			"IP-CIDR,157.240.0.0/16,DIRECT,tcp",
			"#IP-CIDR,10.55.0.0/16,DIRECT"
		]
	}`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))

	origPath, _ := configuration.GetConfigFilePath()
	t.Cleanup(func() { configuration.SetConfigFilePath(origPath) })
	configuration.SetConfigFilePath(cfgPath)

	excludes := collectBypassCidrs()
	var actual []string
	for _, p := range excludes {
		actual = append(actual, p.String())
	}

	assert.Contains(t, actual, "172.16.0.0/12")
	assert.NotContains(t, actual, "57.144.0.0/14")
	assert.NotContains(t, actual, "157.240.0.0/16")
	assert.NotContains(t, actual, "10.55.0.0/16")
}

func TestCollectProcessBypasses_ProtocolQualifiersAndEffectiveRules(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	content := `{
		"setting": {
			"bypassProcesses": ["zoom.exe"]
		},
		"proxy": [],
		"ruleGroups": [
			{"id": "grp-on", "name": "Enabled", "enabled": true, "order": 0},
			{"id": "grp-off", "name": "Disabled", "enabled": false, "order": 1}
		],
		"customizedRules": [
			{
				"id": "p1",
				"groupId": "grp-on",
				"conditions": [{"type": "PROCESS", "value": "WhatsApp.Root.exe"}],
				"policy": {"kind": "direct"},
				"network": "udp",
				"enabled": true,
				"order": 0
			},
			{
				"id": "p2",
				"groupId": "grp-on",
				"conditions": [{"type": "PROCESS", "value": "curl.exe"}],
				"policy": {"kind": "direct"},
				"network": "tcp",
				"enabled": true,
				"order": 1
			},
			{
				"id": "p3",
				"groupId": "grp-on",
				"conditions": [{"type": "PROCESS", "value": "teams.exe"}],
				"policy": {"kind": "direct"},
				"enabled": true,
				"order": 2
			},
			{
				"id": "p4",
				"groupId": "grp-on",
				"conditions": [{"type": "PROCESS", "value": "Zoom.exe"}],
				"policy": {"kind": "direct"},
				"network": "udp",
				"enabled": true,
				"order": 3
			},
			{
				"id": "p5",
				"groupId": "grp-on",
				"conditions": [{"type": "PROCESS", "value": "disabled.exe"}],
				"policy": {"kind": "direct"},
				"enabled": false,
				"order": 4
			},
			{
				"id": "p6",
				"groupId": "grp-off",
				"conditions": [{"type": "PROCESS", "value": "disabledgrp.exe"}],
				"policy": {"kind": "direct"},
				"enabled": true,
				"order": 0
			},
			{
				"id": "p7",
				"groupId": "grp-on",
				"conditions": [{"type": "PROCESS", "value": "unknownproto.exe"}],
				"policy": {"kind": "direct"},
				"network": "icmp",
				"enabled": true,
				"order": 5
			},
			{
				"id": "p8",
				"groupId": "grp-on",
				"conditions": [{"type": "PROCESS", "value": "proxied.exe"}],
				"policy": {"kind": "selected"},
				"enabled": true,
				"order": 6
			}
		],
		"rules": [
			"PROCESS,stale.exe,DIRECT"
		]
	}`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))

	origPath, _ := configuration.GetConfigFilePath()
	t.Cleanup(func() { configuration.SetConfigFilePath(origPath) })
	configuration.SetConfigFilePath(cfgPath)

	rawConfig, err := configuration.Read()
	require.NoError(t, err)
	effective, err := configuration.EffectiveRules()
	require.NoError(t, err)

	got := collectProcessBypasses(rawConfig, effective)
	assert.Equal(t, []processBypassEntry{
		{Process: "zoom.exe", Protocol: constants.RuleProtocolAny},
		{Process: "WhatsApp.Root.exe", Protocol: constants.RuleProtocolUDP},
		{Process: "curl.exe", Protocol: constants.RuleProtocolTCP},
		{Process: "teams.exe", Protocol: constants.RuleProtocolAny},
	}, got)
}

func TestCollectProcessBypasses_LegacyRules(t *testing.T) {
	rawConfig := configuration.Config{
		Rules: []string{
			"PROCESS,WhatsApp.Root.exe,DIRECT,udp",
			"PROCESS,curl.exe,DIRECT,tcp",
			"PROCESS,teams.exe,DIRECT",
			"PROCESS,badproto.exe,DIRECT,icmp",
			"#PROCESS,commented.exe,DIRECT",
			"PROCESS,proxied.exe,PROXY",
		},
	}

	got := collectProcessBypasses(rawConfig, nil)
	assert.Equal(t, []processBypassEntry{
		{Process: "WhatsApp.Root.exe", Protocol: constants.RuleProtocolUDP},
		{Process: "curl.exe", Protocol: constants.RuleProtocolTCP},
		{Process: "teams.exe", Protocol: constants.RuleProtocolAny},
	}, got)
}

func TestCollectDirectBypassCidrs_ShadowingMaskingAndSafetyGuards(t *testing.T) {
	cfg := configuration.Config{
		RuleGroups: []configuration.RuleGroup{
			{Id: "blocked", Name: "Blocked", Enabled: true, Order: 0},
			{Id: "lan", Name: "LAN", Enabled: true, Order: 1},
		},
		CustomizedRules: []configuration.RuleItem{
			// Earlier REJECT shadows overlapping /8 DIRECT below.
			{
				Id:         "b1",
				GroupId:    "blocked",
				Conditions: []configuration.RuleCondition{{Type: "IP-CIDR", Value: "10.1.0.0/16"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindReject},
				Enabled:    true,
				Order:      0,
			},
			// Shadowed by b1 -> must NOT be promoted to L3 route exclude.
			{
				Id:         "d1",
				GroupId:    "lan",
				Conditions: []configuration.RuleCondition{{Type: "IP-CIDR", Value: "10.0.0.0/8"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      0,
			},
			// Non-canonical host bits -> masked and deduplicated.
			{
				Id:         "d2",
				GroupId:    "lan",
				Conditions: []configuration.RuleCondition{{Type: "IP-CIDR", Value: "172.20.5.9/16"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      1,
			},
			{
				Id:         "d3",
				GroupId:    "lan",
				Conditions: []configuration.RuleCondition{{Type: "IP-CIDR", Value: "172.20.0.0/16"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      2,
			},
			// Bare IPv4 host -> /32; bare IPv6 host -> cleanly skipped (no "/32" mangling).
			{
				Id:         "d4",
				GroupId:    "lan",
				Conditions: []configuration.RuleCondition{{Type: "IP-CIDR", Value: "192.168.50.10"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      3,
			},
			{
				Id:         "d5",
				GroupId:    "lan",
				Conditions: []configuration.RuleCondition{{Type: "IP-CIDR", Value: "2001:db8::1"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      4,
			},
			// Safety guards: /0, Fake-IP overlap, TUN gateway & hijacked DNS must be rejected.
			{
				Id:         "d6",
				GroupId:    "lan",
				Conditions: []configuration.RuleCondition{{Type: "IP-CIDR", Value: "0.0.0.0/0"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      5,
			},
			{
				Id:         "d7",
				GroupId:    "lan",
				Conditions: []configuration.RuleCondition{{Type: "IP-CIDR", Value: "198.18.0.0/15"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      6,
			},
			{
				Id:         "d8",
				GroupId:    "lan",
				Conditions: []configuration.RuleCondition{{Type: "IP-CIDR", Value: "198.0.0.0/8"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      7,
			},
			{
				Id:         "d9",
				GroupId:    "lan",
				Conditions: []configuration.RuleCondition{{Type: "IP-CIDR", Value: "10.255.0.0/30"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      8,
			},
			{
				Id:         "d10",
				GroupId:    "lan",
				Conditions: []configuration.RuleCondition{{Type: "IP-CIDR", Value: "10.255.0.2/32"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      9,
			},
		},
	}

	effective := configuration.EffectiveRulesFrom(cfg)
	got := collectDirectBypassCidrsFromRules(cfg, effective)
	var strs []string
	for _, p := range got {
		strs = append(strs, p.String())
	}
	assert.Equal(t, []string{"172.20.0.0/16", "192.168.50.10/32"}, strs)
}

func TestCollectBypassRules_MigratedEmptyDoesNotResurrectLegacy(t *testing.T) {
	// User deleted all customized rules on a migrated store, but stale legacy
	// Rules entries remained on disk -> must NOT fall back to legacy Rules.
	cfg := configuration.Config{
		RuleGroups:      []configuration.RuleGroup{{Id: "g1", Name: "LAN", Enabled: true}},
		CustomizedRules: nil,
		NextRuleId:      5,
		Rules: []string{
			"IP-CIDR,172.16.0.0/12,DIRECT",
			"PROCESS,stale.exe,DIRECT",
		},
	}
	effective := configuration.EffectiveRulesFrom(cfg)
	assert.Empty(t, collectDirectBypassCidrsFromRules(cfg, effective))
	assert.Empty(t, collectProcessBypasses(cfg, effective))
}

func TestCollectProcessBypasses_ShadowingAndMixedCaseNetwork(t *testing.T) {
	cfg := configuration.Config{
		RuleGroups: []configuration.RuleGroup{
			{Id: "blocked", Name: "Blocked", Enabled: true, Order: 0},
			{Id: "allow", Name: "Allow", Enabled: true, Order: 1},
		},
		CustomizedRules: []configuration.RuleItem{
			// Unscoped REJECT shadows any later DIRECT for curl.exe.
			{
				Id:         "b1",
				GroupId:    "blocked",
				Conditions: []configuration.RuleCondition{{Type: "PROCESS", Value: "curl.exe"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindReject},
				Enabled:    true,
				Order:      0,
			},
			// TCP-only REJECT for hybrid.exe shadows unscoped DIRECT and TCP DIRECT,
			// but still allows an explicit UDP-only DIRECT permit.
			{
				Id:         "b2",
				GroupId:    "blocked",
				Conditions: []configuration.RuleCondition{{Type: "PROCESS", Value: "hybrid.exe"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindReject},
				Network:    "Tcp",
				Enabled:    true,
				Order:      1,
			},
			{
				Id:         "a1",
				GroupId:    "allow",
				Conditions: []configuration.RuleCondition{{Type: "PROCESS", Value: "curl.exe"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      0,
			},
			{
				Id:         "a2",
				GroupId:    "allow",
				Conditions: []configuration.RuleCondition{{Type: "PROCESS", Value: "hybrid.exe"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Enabled:    true,
				Order:      1,
			},
			{
				Id:         "a3",
				GroupId:    "allow",
				Conditions: []configuration.RuleCondition{{Type: "PROCESS", Value: "hybrid.exe"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Network:    " Udp ",
				Enabled:    true,
				Order:      2,
			},
			{
				Id:         "a4",
				GroupId:    "allow",
				Conditions: []configuration.RuleCondition{{Type: "PROCESS", Value: "mixedcase.exe"}},
				Policy:     configuration.RulePolicy{Kind: configuration.PolicyKindDirect},
				Network:    "Tcp",
				Enabled:    true,
				Order:      3,
			},
		},
	}

	effective := configuration.EffectiveRulesFrom(cfg)
	got := collectProcessBypasses(cfg, effective)
	assert.Equal(t, []processBypassEntry{
		{Process: "hybrid.exe", Protocol: constants.RuleProtocolUDP},
		{Process: "mixedcase.exe", Protocol: constants.RuleProtocolTCP},
	}, got)
}
