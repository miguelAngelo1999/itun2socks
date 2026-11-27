package configuration

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDirectBypassEntriesFrom_FiltersScopedCompoundAndShadowedRules(t *testing.T) {
	cfg := Config{
		RuleGroups: []RuleGroup{
			{Id: "blocked", Name: "Blocked", Enabled: true, Order: 0},
			{Id: "direct", Name: "Direct", Enabled: true, Order: 1},
		},
		CustomizedRules: []RuleItem{
			// Earlier REJECT rules that must block OS-proxy bypass promotion below.
			{
				Id:         "b1",
				GroupId:    "blocked",
				Conditions: []RuleCondition{{Type: "IP-CIDR", Value: "10.1.0.0/16"}},
				Policy:     RulePolicy{Kind: PolicyKindReject},
				Enabled:    true,
				Order:      0,
			},
			{
				Id:         "b2",
				GroupId:    "blocked",
				Conditions: []RuleCondition{{Type: "DOMAIN", Value: "ads.example.com"}},
				Policy:     RulePolicy{Kind: PolicyKindReject},
				Enabled:    true,
				Order:      1,
			},
			{
				Id:         "b3",
				GroupId:    "blocked",
				Conditions: []RuleCondition{{Type: "DOMAIN-SUFFIX", Value: "bad.org"}},
				Policy:     RulePolicy{Kind: PolicyKindReject},
				Enabled:    true,
				Order:      2,
			},
			// Shadowed DIRECT rules -> must be omitted from OS proxy exception list.
			{
				Id:         "d-shadow-cidr",
				GroupId:    "direct",
				Conditions: []RuleCondition{{Type: "IP-CIDR", Value: "10.0.0.0/8"}},
				Policy:     RulePolicy{Kind: PolicyKindDirect},
				Enabled:    true,
				Order:      0,
			},
			{
				Id:         "d-shadow-suffix",
				GroupId:    "direct",
				Conditions: []RuleCondition{{Type: "DOMAIN-SUFFIX", Value: "example.com"}},
				Policy:     RulePolicy{Kind: PolicyKindDirect},
				Enabled:    true,
				Order:      1,
			},
			{
				Id:         "d-shadow-domain",
				GroupId:    "direct",
				Conditions: []RuleCondition{{Type: "DOMAIN", Value: "sub.bad.org"}},
				Policy:     RulePolicy{Kind: PolicyKindDirect},
				Enabled:    true,
				Order:      2,
			},
			{
				Id:         "d-shadow-keyword",
				GroupId:    "direct",
				Conditions: []RuleCondition{{Type: "DOMAIN-KEYWORD", Value: "bad"}},
				Policy:     RulePolicy{Kind: PolicyKindDirect},
				Enabled:    true,
				Order:      3,
			},
			// Protocol-scoped and compound DIRECT rules -> must be skipped.
			{
				Id:         "d-udp",
				GroupId:    "direct",
				Conditions: []RuleCondition{{Type: "IP-CIDR", Value: "57.144.0.0/14"}},
				Policy:     RulePolicy{Kind: PolicyKindDirect},
				Network:    "udp",
				Enabled:    true,
				Order:      4,
			},
			{
				Id:         "d-tcp",
				GroupId:    "direct",
				Conditions: []RuleCondition{{Type: "DOMAIN", Value: "tcp-only.local"}},
				Policy:     RulePolicy{Kind: PolicyKindDirect},
				Network:    "tcp",
				Enabled:    true,
				Order:      5,
			},
			{
				Id:      "d-compound",
				GroupId: "direct",
				Conditions: []RuleCondition{
					{Type: "IP-CIDR", Value: "192.168.77.0/24"},
					{Type: "PROCESS", Value: "app.exe"},
				},
				Policy:  RulePolicy{Kind: PolicyKindDirect},
				Enabled: true,
				Order:   6,
			},
			// Clean unshadowed single-condition DIRECT rules -> must be included.
			{
				Id:         "d-ok-cidr",
				GroupId:    "direct",
				Conditions: []RuleCondition{{Type: "IP-CIDR", Value: "192.168.61.0/24"}},
				Policy:     RulePolicy{Kind: PolicyKindDirect},
				Enabled:    true,
				Order:      7,
			},
			{
				Id:         "d-ok-domain",
				GroupId:    "direct",
				Conditions: []RuleCondition{{Type: "DOMAIN", Value: "printer.lan"}},
				Policy:     RulePolicy{Kind: PolicyKindDirect},
				Enabled:    true,
				Order:      8,
			},
			{
				Id:         "d-ok-suffix",
				GroupId:    "direct",
				Conditions: []RuleCondition{{Type: "DOMAIN-SUFFIX", Value: "intranet.local"}},
				Policy:     RulePolicy{Kind: PolicyKindDirect},
				Enabled:    true,
				Order:      9,
			},
		},
	}

	got := DirectBypassEntriesFrom(cfg)
	assert.Equal(t, []string{
		"192.168.61.*",
		"printer.lan",
		"*.intranet.local",
		"intranet.local",
	}, got)
}
