package conn

import (
	"fmt"
	"net"
	"strings"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/pac"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
)

// PacMatcher checks active PAC rules for DIRECT domains/CIDRs.
// If the destination matches a PAC DIRECT rule, returns DIRECT.
// This is always in the matcher chain but is a no-op when no PAC rules are active.
func PacMatcher(metadata *C.Metadata, prevRule rule_engine.Rule) (rule_engine.Rule, error) {
	rules := pac.GetActiveRules()
	if len(rules) == 0 {
		return nil, fmt.Errorf("no pac rules")
	}

	host := metadata.Host
	dstIP := metadata.DstIP.String()

	for _, r := range rules {
		if r.Policy != "DIRECT" {
			continue
		}

		switch r.Type {
		case "DOMAIN-SUFFIX":
			if host != "" && matchDomainSuffix(host, r.Payload) {
				return rule_engine.BuiltInDirectRule, nil
			}
		case "DOMAIN":
			if host != "" && strings.EqualFold(host, r.Payload) {
				return rule_engine.BuiltInDirectRule, nil
			}
		case "IP-CIDR":
			if dstIP != "" {
				_, cidrNet, err := net.ParseCIDR(r.Payload)
				if err == nil && cidrNet.Contains(net.ParseIP(dstIP)) {
					return rule_engine.BuiltInDirectRule, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no pac match")
}

func matchDomainSuffix(host, suffix string) bool {
	host = strings.ToLower(host)
	suffix = strings.ToLower(suffix)
	if host == suffix {
		return true
	}
	return strings.HasSuffix(host, "."+suffix)
}
