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
	named := make(map[constants.Policy]C.Proxy, len(namedProxies))
	for k, v := range namedProxies {
		named[k] = v
	}
	proxies = named
	proxies[constants.PolicyProxy] = remoteProxy
	proxies[constants.PolicyDirect] = adapter.NewProxy(outbound.NewDirect())
	proxies[constants.PolicyReject] = adapter.NewProxy(outbound.NewReject())
}

// namedProxies holds dialers for proxies addressable by id, so a rule can route
// to one specific proxy rather than whichever is currently selected.
//
// Kept separate from proxies because UpdateProxy rebuilds that map whenever the
// selected proxy changes, and the named set must survive that.
var namedProxies = map[constants.Policy]C.Proxy{}

// UpdateNamedProxies replaces the set of individually addressable proxies.
// Keys are proxy ids; a rule whose policy is that id dials through it.
func UpdateNamedProxies(byId map[string]C.Proxy) {
	mux.Lock()
	defer mux.Unlock()
	namedProxies = make(map[constants.Policy]C.Proxy, len(byId))
	for id, p := range byId {
		if constants.IsBuiltInPolicy(constants.Policy(id)) {
			// A proxy id colliding with a built-in policy name would shadow it.
			log.Warnln(log.FormatLog(log.ConfigurationPrefix,
				"ignoring proxy id %q: it collides with a built-in policy"), id)
			continue
		}
		namedProxies[constants.Policy(id)] = p
		proxies[constants.Policy(id)] = p
	}
}

// NamedProxyIds lists the ids currently dialable, for validating rules.
func NamedProxyIds() []string {
	mux.RLock()
	defer mux.RUnlock()
	ids := make([]string, 0, len(namedProxies))
	for k := range namedProxies {
		ids = append(ids, string(k))
	}
	return ids
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
