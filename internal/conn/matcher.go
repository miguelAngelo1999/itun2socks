package conn

import (
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/dns"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// proxyNameCache maps a proxy id → its human name for the connection log.
// The log line runs on the per-connection hot path, so we cache the id→name
// lookup with a short TTL instead of reading the config on every connection.
var (
	proxyNameMux   sync.RWMutex
	proxyNameCache = map[string]string{}
	proxyNameAt    time.Time
)

const proxyNameTTL = 30 * time.Second

// policyDisplayName returns a human-friendly label for a rule policy for
// logging. Built-in policies (DIRECT/PROXY/REJECT) and other non-id labels are
// returned unchanged; a proxy id is resolved to the proxy's name (falling back
// to the id if the name can't be found). Never returns empty.
func policyDisplayName(policy string) string {
	if policy == "" {
		return policy
	}
	if constants.IsBuiltInPolicy(constants.Policy(policy)) {
		return policy
	}

	proxyNameMux.RLock()
	name, ok := proxyNameCache[policy]
	fresh := time.Since(proxyNameAt) < proxyNameTTL
	proxyNameMux.RUnlock()
	if ok && fresh {
		return name
	}

	// Refresh the cache from config. On any failure, fall back to the id so the
	// log line is never blank or wrong.
	if p, err := configuration.GetProxy(policy); err == nil {
		if n, _ := p["name"].(string); n != "" {
			proxyNameMux.Lock()
			proxyNameCache[policy] = n
			proxyNameAt = time.Now()
			proxyNameMux.Unlock()
			return n
		}
	}
	return policy
}

var defaultConnMatchers []Matcher
var matcherMux sync.RWMutex

func UpdateConnMatcher(matchers []Matcher) {
	matcherMux.Lock()
	defer matcherMux.Unlock()
	defaultConnMatchers = matchers
}

func GetConnMatcher() []Matcher {
	matcherMux.RLock()
	defer matcherMux.RUnlock()
	return defaultConnMatchers
}

func GetIsDNSConn(metadata *C.Metadata) bool {
	return metadata.NetWork == C.UDP && metadata.DstPort.String() == constants.DnsPort
}

func resolveMetadata(metadata *C.Metadata) rule_engine.Rule {

	var logType = log.TcpPrefix
	var printLog = log.Infoln

	var rule rule_engine.Rule = rule_engine.BuiltInProxyRule
	for _, matcher := range GetConnMatcher() {
		tempRule, err := matcher(metadata, rule)
		if err == nil {
			rule = tempRule
		}
	}
	remoteAddr := metadata.DstIP.String()
	if metadata.NetWork == C.UDP {
		logType = log.UdpPrefix
	}
	if GetIsDNSConn(metadata) {
		printLog = log.Debugln
	}
	cachedDomain, ok := dns.GetCachedDnsItem(remoteAddr)
	if rule.GetPolicy() == constants.PolicyReject {
		// Log denied connections at warn level so they appear in orange in the
		// log view and are easy to spot without filtering.
		if ok {
			log.Warnln(log.FormatLog(logType, " [DENY] %s to %s(%s) matched rule: %s"), metadata.SourceAddress(), metadata.RemoteAddress(), cachedDomain, rule.GetPolicy())
		} else {
			log.Warnln(log.FormatLog(logType, " [DENY] %s to %s matched rule: %s"), metadata.SourceAddress(), metadata.RemoteAddress(), rule.GetPolicy())
		}
	} else if ok {
		printLog(log.FormatLog(logType, " %s to %s(%s) using %s"), metadata.SourceAddress(), metadata.RemoteAddress(), cachedDomain, policyDisplayName(string(rule.GetPolicy())))
	} else {
		printLog(log.FormatLog(logType, " %s to %s using %s"), metadata.SourceAddress(), metadata.RemoteAddress(), policyDisplayName(string(rule.GetPolicy())))
	}
	return rule
}
