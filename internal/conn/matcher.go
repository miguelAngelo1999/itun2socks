package conn

import (
	"fmt"
	"strings"
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

// ResolvePolicyLabel returns a clear human label for a routing policy, including
// the active selected proxy name when policy == PROXY (e.g. "PROXY (test-proxy)").
func ResolvePolicyLabel(policy constants.Policy) string {
	if policy == constants.PolicyProxy {
		if id := GetSelectedProxyId(); id != "" {
			if name := policyDisplayName(id); name != "" && name != id {
				return fmt.Sprintf("PROXY (%s)", name)
			}
		}
		if p, err := GetProxy(constants.PolicyProxy); err == nil && p != nil {
			if name := strings.TrimSpace(p.Name()); name != "" && name != "PROXY" {
				return fmt.Sprintf("PROXY (%s)", name)
			}
		}
		return string(policy)
	}
	return policyDisplayName(string(policy))
}

// FormatTargetForLog returns a concise host:port target, enriching bare IP
// destinations with the cached DNS domain when available (e.g. TUN mode).
func FormatTargetForLog(metadata *C.Metadata) string {
	if metadata == nil {
		return "unknown"
	}
	remote := metadata.RemoteAddress()
	if metadata.Host != "" {
		return remote
	}
	if metadata.DstIP != nil {
		if cached, ok := dns.GetCachedDnsItem(metadata.DstIP.String()); ok && cached != "" {
			if metadata.DstPort > 0 {
				return fmt.Sprintf("%s:%s (%s)", cached, metadata.DstPort.String(), metadata.DstIP.String())
			}
			return fmt.Sprintf("%s (%s)", cached, remote)
		}
	}
	return remote
}

// FormatProcessTag returns " [AppName]" when metadata carries a process path,
// or "" otherwise. Handles both POSIX '/' and Windows '\' separators.
func FormatProcessTag(metadata *C.Metadata) string {
	if metadata == nil || metadata.ProcessPath == "" {
		return ""
	}
	p := strings.TrimSpace(metadata.ProcessPath)
	if idx := strings.LastIndexAny(p, `/\`); idx >= 0 && idx+1 < len(p) {
		p = p[idx+1:]
	}
	if p == "" {
		return ""
	}
	return " [" + p + "]"
}

func formatMatchedRuleTag(rule rule_engine.Rule) string {
	if rule == nil {
		return ""
	}
	rt := rule.Type()
	val := strings.TrimSpace(rule.Value())
	if rt == "" || rt == constants.RuleBuiltIn {
		return ""
	}
	if val != "" {
		return fmt.Sprintf("%s:%s", rt, val)
	}
	return string(rt)
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
	if metadata.NetWork == C.UDP {
		logType = log.UdpPrefix
	}
	if GetIsDNSConn(metadata) {
		printLog = log.Debugln
	}

	target := FormatTargetForLog(metadata)
	procTag := FormatProcessTag(metadata)
	ruleTag := formatMatchedRuleTag(rule)

	if rule.GetPolicy() == constants.PolicyReject {
		// Log locally rejected connections at warn level with [RULE_REJECT] so
		// the UI can distinguish Lux rules from upstream proxy denials.
		if ruleTag != "" {
			log.Warnln(log.FormatLog(logType, "[DENY] [RULE_REJECT] %s%s matched %s → REJECT"), target, procTag, ruleTag)
		} else {
			log.Warnln(log.FormatLog(logType, "[DENY] [RULE_REJECT] %s%s matched rule: REJECT"), target, procTag)
		}
		return rule
	}

	policyLabel := ResolvePolicyLabel(rule.GetPolicy())
	if ruleTag != "" {
		printLog(log.FormatLog(logType, "%s%s → %s (%s)"), target, procTag, policyLabel, ruleTag)
	} else {
		printLog(log.FormatLog(logType, "%s%s → %s"), target, procTag, policyLabel)
	}
	return rule
}
