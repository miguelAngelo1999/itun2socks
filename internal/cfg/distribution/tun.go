package distribution

import (
	"fmt"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/dns"
	"github.com/igoogolx/itun2socks/internal/matcher"
	"github.com/igoogolx/itun2socks/pkg/clash/component/fakeip"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
)

type Config struct {
	Dns DnsDistribution
}

// networkToProtocol converts the clash NetWork enum to the RuleProtocol
// used by the rule engine protocol filter (Requirements 7.1, 7.2, 7.3).
func networkToProtocol(network C.NetWork) constants.RuleProtocol {
	if network == C.UDP {
		return constants.RuleProtocolUDP
	}
	return constants.RuleProtocolTCP
}

func (c Config) ConnMatcher(metadata *C.Metadata, _ rule_engine.Rule) (rule_engine.Rule, error) {
	proto := networkToProtocol(metadata.NetWork)

	processPath := metadata.ProcessPath
	if len(processPath) != 0 {
		if rule, err := matcher.GetRuleEngine().MatchWithProtocol(processPath, constants.ProcessRuleTypes, proto); err == nil {
			return rule, nil
		}
	}

	ip := metadata.DstIP.String()
	if len(ip) != 0 {
		if rule, err := matcher.GetRuleEngine().MatchWithProtocol(ip, constants.IpRuleTypes, proto); err == nil {
			return rule, nil
		}
	}

	// DST-PORT matching: evaluate rules whose type is DST-PORT against the
	// destination port number (Requirement 2.4, 2.5).
	port := metadata.DstPort.String()
	if port != "" && port != "0" {
		if rule, err := matcher.GetRuleEngine().MatchWithProtocol(port, constants.DstPortRuleTypes, proto); err == nil {
			return rule, nil
		}
	}

	host := metadata.Host
	if len(host) != 0 {
		var rule, err = matcher.GetRuleEngine().MatchWithProtocol(host, constants.DomainRuleTypes, proto)
		if err == nil {
			return rule, nil
		}
	}

	return nil, fmt.Errorf("no rule found")
}

func NewTun(
	boostDns []string,
	remoteDns []string,
	localDns []string,
	defaultInterfaceName string,
	disableCache bool,
	fakeIpPool *fakeip.Pool,
) (Config, error) {
	if len(boostDns) == 0 || len(remoteDns) == 0 || len(localDns) == 0 {
		return Config{}, fmt.Errorf("dns can't be empty")
	}

	dns.ResetCache()
	dnsConfig, err := NewDnsDistribution(boostDns, remoteDns, localDns, defaultInterfaceName, disableCache, fakeIpPool)
	if err != nil {
		return Config{}, err
	}

	return Config{
		dnsConfig,
	}, nil
}
