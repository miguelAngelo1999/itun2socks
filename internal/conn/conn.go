package conn

import (
	"fmt"
	"strings"
	"sync"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/dns"
	"github.com/igoogolx/itun2socks/pkg/clash/adapter"
	"github.com/igoogolx/itun2socks/pkg/clash/adapter/outbound"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	"github.com/igoogolx/itun2socks/pkg/log"
)

var defaultIsFakeIpEnabled bool

func UpdateIsFakeIpEnabled(value bool) {
	mux.Lock()
	defer mux.Unlock()
	defaultIsFakeIpEnabled = value
}

var (
	proxies map[constants.Policy]C.Proxy
	mux     sync.RWMutex
)

type Matcher func(metadata *C.Metadata, rule rule_engine.Rule) (rule_engine.Rule, error)

func RejectQuicMather(metadata *C.Metadata, prevRule rule_engine.Rule) (rule_engine.Rule, error) {
	if prevRule.GetPolicy() == constants.PolicyProxy && strings.Contains(metadata.NetWork.String(), "udp") && metadata.DstPort.String() == "443" {
		log.Debugln("reject quic conn:%v", metadata.RemoteAddress())
		return rule_engine.BuiltInRejectRule, nil
	}
	return nil, fmt.Errorf("not quic")
}

func UpdateProxy(remoteProxy C.Proxy) {
	mux.Lock()
	defer mux.Unlock()
	proxies = make(map[constants.Policy]C.Proxy)
	proxies[constants.PolicyProxy] = remoteProxy
	proxies[constants.PolicyDirect] = adapter.NewProxy(outbound.NewDirect())
	proxies[constants.PolicyReject] = adapter.NewProxy(outbound.NewReject())

	// Check if selected proxy is DIRECT - if so, all named proxy policies
	// should also route direct (home mode: no proxy for anything)
	selectedId, _ := configuration.GetSelectedId("proxy")
	isDirectMode := selectedId == "DIRECT"

	// Register named proxies for per-profile rule routing
	if config, err := configuration.Read(); err == nil {
		for _, proxyConfig := range config.Proxy {
			name, _ := proxyConfig["name"].(string)
			id, _ := proxyConfig["id"].(string)
			if name == "" && id == "" {
				continue
			}
			var proxy C.Proxy
			if isDirectMode {
				// In direct mode, all named proxies route directly
				proxy = adapter.NewProxy(outbound.NewDirect())
			} else {
				if p, err := adapter.ParseProxy(proxyConfig); err == nil {
					proxy = adapter.NewProxy(p)
				}
			}
			if proxy != nil {
				if name != "" {
					proxies[constants.Policy(name)] = proxy
				}
				if id != "" {
					proxies[constants.Policy(id)] = proxy
				}
			}
		}
	}
}

func GetProxy(rule constants.Policy) (C.Proxy, error) {
	mux.RLock()
	defer mux.RUnlock()
	connDialer := proxies[rule]
	if connDialer == nil {
		return nil, fmt.Errorf("empty dialer")
	}
	return connDialer, nil
}

func handleMetadata(metadata *C.Metadata) rule_engine.Rule {

	rule := resolveMetadata(metadata)

	if rule.Type() == constants.RuleDnsMap {
		dnsMapRule, ok := rule.(*rule_engine.DnsMap)
		if ok {
			ip, err := dnsMapRule.GetIp()
			if err == nil {
				log.Infoln(log.FormatLog(log.DnsPrefix, "query dns from DNS-MAP rule, question: %v, result: %v"), metadata.Host, ip.String())
				metadata.DstIP = ip
				metadata.Host = ""
			}
		}
	}

	if rule.GetPolicy() == constants.PolicyProxy && defaultIsFakeIpEnabled {
		hostByFakeIp, ok := dns.FakeIpPool.LookBack(metadata.DstIP)
		if ok {
			metadata.Host = hostByFakeIp
		}
	}
	return rule
}
