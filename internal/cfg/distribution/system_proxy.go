package distribution

import (
	"fmt"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/dns"
	"github.com/igoogolx/itun2socks/internal/matcher"
	cResolver "github.com/igoogolx/itun2socks/pkg/clash/component/resolver"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
)

type SystemProxyConfig struct {
}

func (c SystemProxyConfig) ConnMatcher(metadata *C.Metadata, _ rule_engine.Rule) (rule_engine.Rule, error) {
	proto := networkToProtocol(metadata.NetWork)

	if metadata.Host != "" {
		var rule, err = matcher.GetRuleEngine().MatchWithProtocol(metadata.Host, constants.DomainRuleTypes, proto)
		if err == nil {
			return rule, nil
		}
	}

	if metadata.DstIP.String() != "" {
		rule, err := matcher.GetRuleEngine().MatchWithProtocol(metadata.DstIP.String(), constants.IpRuleTypes, proto)
		if err == nil {
			return rule, nil
		}
	}

	// DST-PORT matching (Requirement 2.4, 2.5).
	port := metadata.DstPort.String()
	if port != "" && port != "0" {
		if rule, err := matcher.GetRuleEngine().MatchWithProtocol(port, constants.DstPortRuleTypes, proto); err == nil {
			return rule, nil
		}
	}

	return nil, fmt.Errorf("no rule found")

}

func NewSystemProxy() (SystemProxyConfig, error) {
	dns.ResetCache()
	cResolver.DefaultResolver = nil
	return SystemProxyConfig{}, nil
}
