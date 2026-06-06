package conn

import (
	"fmt"
	"strings"
	"sync"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
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
	proxies      map[constants.Policy]C.Proxy
	namedProxies map[string]C.Proxy
	mux          sync.RWMutex
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
}

// SetNamedProxies initializes adapters for proxies referenced by name in rules
func SetNamedProxies(proxyConfigs []map[string]any) {
	mux.Lock()
	defer mux.Unlock()
	namedProxies = make(map[string]C.Proxy)
	for _, cfg := range proxyConfigs {
		name, _ := cfg["name"].(string)
		if name == "" {
			continue
		}
		p, err := adapter.ParseProxy(cfg)
		if err != nil {
			log.Warnln(log.FormatLog(log.HubPrefix, "fail to parse named proxy '%v': %v"), name, err)
			continue
		}
		namedProxies[strings.ToLower(name)] = adapter.NewProxy(p)
		log.Infoln(log.FormatLog(log.HubPrefix, "loaded named proxy: %v"), name)
	}
}

// GetProxyForPolicy resolves a policy to a proxy - supports named proxies
func GetProxyForPolicy(policy constants.Policy) (C.Proxy, error) {
	mux.RLock()
	defer mux.RUnlock()

	if constants.IsNamedProxy(policy) {
		if p, ok := namedProxies[strings.ToLower(string(policy))]; ok {
			return p, nil
		}
		// Fallback to default selected proxy
		if p := proxies[constants.PolicyProxy]; p != nil {
			return p, nil
		}
		return nil, fmt.Errorf("named proxy '%v' not found", policy)
	}
	return GetProxy(policy)
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
