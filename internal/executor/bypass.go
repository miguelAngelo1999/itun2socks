package executor

import (
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/pkg/log"
)

var (
	activeBypassMu       sync.RWMutex
	activeBypassPrefixes []netip.Prefix
)

func updateActiveBypassPrefixes(prefixes []netip.Prefix) {
	activeBypassMu.Lock()
	defer activeBypassMu.Unlock()
	activeBypassPrefixes = prefixes
}

// IsBypassedFromTun reports whether the given IP is covered by the active TUN bypass CIDRs.
func IsBypassedFromTun(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip4)
	if !ok {
		return false
	}
	activeBypassMu.RLock()
	defer activeBypassMu.RUnlock()
	for _, prefix := range activeBypassPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func addHostToBypass(host string, excludes *[]netip.Prefix, seen map[netip.Prefix]bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() {
			pfx := netip.PrefixFrom(addr, 32)
			if !seen[pfx] {
				seen[pfx] = true
				*excludes = append(*excludes, pfx)
			}
		}
		return
	}

	// Resolve hostname (using pac.GoLookup to avoid Fake-IP)
	ipStr := pac.GoLookup(host)
	if ipStr != "" {
		if addr, err := netip.ParseAddr(ipStr); err == nil && addr.Is4() {
			pfx := netip.PrefixFrom(addr, 32)
			if !seen[pfx] {
				seen[pfx] = true
				*excludes = append(*excludes, pfx)
			}
		}
	}
}

// collectBypassCidrs gathers all IP prefixes that should bypass the TUN interface
// entirely at the routing table level. Traffic to these IPs never enters userspace.
//
// Sources (in order):
//  1. Explicit bypassCidrs from settings
//  2. All configured proxy server IPs (resolved if hostnames)
//  3. All PAC URL hosts from pac.DefaultRegistry
//  4. All PAC-declared upstream hosts from pac.DefaultRegistry
//  5. IP-CIDR rules with DIRECT policy from customized rules
func collectBypassCidrs() []netip.Prefix {
	var excludes []netip.Prefix
	seen := make(map[netip.Prefix]bool)

	rawConfig, err := configuration.Read()
	if err != nil {
		log.Warnln(log.FormatLog(log.ExecutorPrefix, "bypass: failed to read config: %v"), err)
		return nil
	}

	// 1. Explicit bypassCidrs from settings
	for _, cidr := range rawConfig.Setting.BypassCidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		prefix, ok := parseSafeBypassIPv4Prefix(cidr)
		if !ok {
			log.Warnln(log.FormatLog(log.ExecutorPrefix, "bypass: skipping invalid or unsafe CIDR %q"), cidr)
			continue
		}
		if !seen[prefix] {
			seen[prefix] = true
			excludes = append(excludes, prefix)
		}
	}

	// 2. Auto-extract ALL proxy server IPs (resolve hostnames)
	for _, p := range rawConfig.Proxy {
		server, _ := p["server"].(string)
		addHostToBypass(server, &excludes, seen)
	}

	// 3. Auto-extract PAC URL hosts
	for _, h := range pac.DefaultRegistry.GetPacHosts() {
		addHostToBypass(h, &excludes, seen)
	}

	// 4. Auto-extract PAC upstream hosts
	for _, h := range pac.DefaultRegistry.GetUpstreamHosts() {
		addHostToBypass(h, &excludes, seen)
	}

	// 5. Extract unscoped, unshadowed IP-CIDR,x,DIRECT rules from the same
	// config snapshot. Protocol-scoped rules (tcp/udp) MUST NOT be added to TUN
	// route excludes because OS routing tables operate at L3 (all protocols) and
	// would create a split-route blackhole for the other transport protocol.
	effective := configuration.EffectiveRulesFrom(rawConfig)
	for _, prefix := range collectDirectBypassCidrsFromRules(rawConfig, effective) {
		if !seen[prefix] {
			seen[prefix] = true
			excludes = append(excludes, prefix)
		}
	}

	updateActiveBypassPrefixes(excludes)

	if len(excludes) > 0 {
		log.Infoln(log.FormatLog(log.ExecutorPrefix, "bypass: %d prefixes excluded from TUN routing"), len(excludes))
	}

	return excludes
}

// isMigratedRuleStore reports whether the config has moved onto the structured
// rule store (so legacy flat Config.Rules must not be used as a fallback even
// if the user later deletes every customized rule).
func isMigratedRuleStore(rawConfig configuration.Config) bool {
	return len(rawConfig.CustomizedRules) > 0 ||
		len(rawConfig.RuleGroups) > 0 ||
		rawConfig.NextRuleId > 0 ||
		rawConfig.NextGroupId > 0
}

// parseNormalizedIPv4Prefix parses a bare IPv4 address or IPv4 CIDR and masks
// host bits so equivalent prefixes deduplicate cleanly. Bare IPv6 addresses are
// parsed with ParseAddr instead of blindly appending "/32".
func parseNormalizedIPv4Prefix(raw string) (netip.Prefix, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, false
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		if !addr.Is4() {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(addr, 32), true
	}
	pfx, err := netip.ParsePrefix(raw)
	if err != nil || !pfx.Addr().Is4() {
		return netip.Prefix{}, false
	}
	return pfx.Masked(), true
}

var (
	rfc2544FakeIpPrefix = netip.MustParsePrefix("198.18.0.0/15")
)

// isUnsafeTunBypassPrefix rejects prefixes that would disable or blackhole the
// TUN stack: /0 default routes, anything overlapping the Fake-IP pool (which
// relies on the TUN default route), or prefixes at/inside the TUN gateway /
// hijacked DNS /30 subnet. Broader RFC1918 LAN prefixes like 10.0.0.0/8 remain
// allowed because the TUN interface's more-specific /30 on-link route wins.
func isUnsafeTunBypassPrefix(pfx netip.Prefix) bool {
	if !pfx.IsValid() || pfx.Bits() == 0 {
		return true
	}
	if rfc2544FakeIpPrefix.Overlaps(pfx) {
		return true
	}
	if fakePfx, err := netip.ParsePrefix(constants.FakeIpRange); err == nil {
		if fakePfx.Masked().Overlaps(pfx) {
			return true
		}
	}
	if tunPfx, err := netip.ParsePrefix(constants.TunGateway); err == nil {
		tunPfx = tunPfx.Masked()
		if tunPfx.Overlaps(pfx) && pfx.Bits() >= tunPfx.Bits() {
			return true
		}
	}
	if dnsAddr, err := netip.ParseAddr(constants.HijackedDns); err == nil && dnsAddr.Is4() {
		dnsPfx := netip.PrefixFrom(dnsAddr, 32)
		if dnsPfx.Overlaps(pfx) && pfx.Bits() >= 30 {
			return true
		}
	}
	return false
}

func parseSafeBypassIPv4Prefix(raw string) (netip.Prefix, bool) {
	pfx, ok := parseNormalizedIPv4Prefix(raw)
	if !ok || isUnsafeTunBypassPrefix(pfx) {
		return netip.Prefix{}, false
	}
	return pfx, true
}

// collectDirectBypassCidrsFromRules extracts unscoped, unshadowed IP-CIDR
// DIRECT prefixes suitable for L3 TUN route exclusion. Uses EffectiveRules when
// the structured rule store is migrated (honoring disabled rules, disabled
// groups, broken status, and evaluation order), falling back to legacy flat
// Rules only on un-migrated configs.
func collectDirectBypassCidrsFromRules(rawConfig configuration.Config, effective []configuration.RuleItem) []netip.Prefix {
	var out []netip.Prefix
	seen := make(map[netip.Prefix]bool)
	var blockingCidrs []netip.Prefix

	isShadowed := func(pfx netip.Prefix) bool {
		for _, b := range blockingCidrs {
			if b.Overlaps(pfx) {
				return true
			}
		}
		return false
	}

	addCidr := func(payload string) {
		pfx, ok := parseSafeBypassIPv4Prefix(payload)
		if !ok || isShadowed(pfx) || seen[pfx] {
			return
		}
		seen[pfx] = true
		out = append(out, pfx)
	}

	if isMigratedRuleStore(rawConfig) {
		for _, r := range effective {
			if r.Policy.Kind != configuration.PolicyKindDirect {
				for _, cond := range r.Conditions {
					if strings.EqualFold(strings.TrimSpace(cond.Type), string(constants.RuleIpCidr)) {
						if pfx, ok := parseNormalizedIPv4Prefix(cond.Value); ok {
							blockingCidrs = append(blockingCidrs, pfx)
						}
					}
				}
				continue
			}
			// Skip protocol-scoped rules (tcp/udp): L3 routes bypass ALL protocols.
			if strings.TrimSpace(r.Network) != "" {
				continue
			}
			// Only promote single-condition IP-CIDR rules so compound rules
			// (e.g. IP-CIDR + PROCESS) are not over-broadened at L3.
			if len(r.Conditions) != 1 {
				continue
			}
			cond := r.Conditions[0]
			if !strings.EqualFold(strings.TrimSpace(cond.Type), string(constants.RuleIpCidr)) {
				continue
			}
			addCidr(cond.Value)
		}
		return out
	}

	// Legacy un-migrated config fallback (no structured rule store yet).
	for _, raw := range rawConfig.Rules {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.Split(raw, ",")
		if len(parts) < 3 || len(parts) > 4 {
			continue
		}
		ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))
		payload := strings.TrimSpace(parts[1])
		policy := strings.ToUpper(strings.TrimSpace(parts[2]))

		if ruleType != string(constants.RuleIpCidr) {
			continue
		}
		if policy != string(constants.PolicyDirect) {
			if pfx, ok := parseNormalizedIPv4Prefix(payload); ok {
				blockingCidrs = append(blockingCidrs, pfx)
			}
			continue
		}
		// Skip protocol-scoped rules (4th field tcp/udp or any non-empty qualifier).
		if len(parts) == 4 && strings.TrimSpace(parts[3]) != "" {
			continue
		}
		addCidr(payload)
	}
	return out
}

type processBypassEntry struct {
	Process  string
	Protocol constants.RuleProtocol
}

// collectProcessBypasses gathers process bypass entries from Setting.BypassProcesses
// and enabled, unshadowed DIRECT PROCESS rules, preserving any tcp/udp protocol
// qualifier. Uses EffectiveRules when the structured rule store is migrated,
// falling back to legacy flat Rules only on un-migrated configs.
func collectProcessBypasses(rawConfig configuration.Config, effective []configuration.RuleItem) []processBypassEntry {
	var rawEntries []processBypassEntry

	for _, proc := range rawConfig.Setting.BypassProcesses {
		proc = strings.TrimSpace(proc)
		if proc != "" {
			rawEntries = append(rawEntries, processBypassEntry{
				Process:  proc,
				Protocol: constants.RuleProtocolAny,
			})
		}
	}

	// Track earlier non-DIRECT PROCESS rules by lowercased process name -> protocol
	// so a shadowed DIRECT PROCESS rule cannot install a fail-open WFP permit.
	blockedByProc := make(map[string]map[constants.RuleProtocol]bool)
	recordBlocked := func(proc string, proto constants.RuleProtocol) {
		key := strings.ToLower(strings.TrimSpace(proc))
		if key == "" {
			return
		}
		if blockedByProc[key] == nil {
			blockedByProc[key] = make(map[constants.RuleProtocol]bool)
		}
		blockedByProc[key][proto] = true
	}
	isProcShadowed := func(proc string, proto constants.RuleProtocol) bool {
		blocked := blockedByProc[strings.ToLower(strings.TrimSpace(proc))]
		if len(blocked) == 0 {
			return false
		}
		if blocked[constants.RuleProtocolAny] {
			return true
		}
		if proto == constants.RuleProtocolAny {
			// Earlier protocol-specific REJECT/PROXY shadows an unscoped Any permit.
			return blocked[constants.RuleProtocolTCP] || blocked[constants.RuleProtocolUDP]
		}
		return blocked[proto]
	}

	if isMigratedRuleStore(rawConfig) {
		for _, r := range effective {
			netField := strings.TrimSpace(r.Network)
			proto := constants.RuleProtocolAny
			validProto := true
			if netField != "" {
				proto = constants.ParseRuleProtocol(netField)
				if proto == constants.RuleProtocolAny {
					validProto = false
				}
			}

			if r.Policy.Kind != configuration.PolicyKindDirect {
				for _, cond := range r.Conditions {
					if strings.EqualFold(strings.TrimSpace(cond.Type), string(constants.RuleProcess)) {
						// Fail-closed: if the blocking rule had an unrecognized protocol,
						// treat it as blocking Any protocol for that process.
						blockProto := proto
						if !validProto {
							blockProto = constants.RuleProtocolAny
						}
						recordBlocked(cond.Value, blockProto)
					}
				}
				continue
			}
			if !validProto || len(r.Conditions) != 1 {
				continue
			}
			cond := r.Conditions[0]
			if !strings.EqualFold(strings.TrimSpace(cond.Type), string(constants.RuleProcess)) {
				continue
			}
			proc := strings.TrimSpace(cond.Value)
			if proc == "" || isProcShadowed(proc, proto) {
				continue
			}
			rawEntries = append(rawEntries, processBypassEntry{
				Process:  proc,
				Protocol: proto,
			})
		}
	} else {
		for _, raw := range rawConfig.Rules {
			raw = strings.TrimSpace(raw)
			if raw == "" || strings.HasPrefix(raw, "#") {
				continue
			}
			parts := strings.Split(raw, ",")
			if len(parts) < 3 || len(parts) > 4 {
				continue
			}
			ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))
			payload := strings.TrimSpace(parts[1])
			policy := strings.ToUpper(strings.TrimSpace(parts[2]))
			if ruleType != string(constants.RuleProcess) || payload == "" {
				continue
			}
			proto := constants.RuleProtocolAny
			validProto := true
			if len(parts) == 4 && strings.TrimSpace(parts[3]) != "" {
				proto = constants.ParseRuleProtocol(strings.TrimSpace(parts[3]))
				if proto == constants.RuleProtocolAny {
					validProto = false
				}
			}
			if policy != string(constants.PolicyDirect) {
				blockProto := proto
				if !validProto {
					blockProto = constants.RuleProtocolAny
				}
				recordBlocked(payload, blockProto)
				continue
			}
			if !validProto || isProcShadowed(payload, proto) {
				continue
			}
			rawEntries = append(rawEntries, processBypassEntry{
				Process:  payload,
				Protocol: proto,
			})
		}
	}

	// Deduplicate: if a process already has an unscoped (Any) entry, drop narrower
	// protocol-specific entries for the same process.
	hasAny := make(map[string]bool)
	for _, e := range rawEntries {
		if e.Protocol == constants.RuleProtocolAny {
			hasAny[strings.ToLower(e.Process)] = true
		}
	}

	type dedupKey struct {
		proc  string
		proto constants.RuleProtocol
	}
	seen := make(map[dedupKey]bool)
	out := make([]processBypassEntry, 0, len(rawEntries))
	for _, e := range rawEntries {
		lower := strings.ToLower(e.Process)
		if e.Protocol != constants.RuleProtocolAny && hasAny[lower] {
			continue
		}
		k := dedupKey{proc: lower, proto: e.Protocol}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	return out
}

// getSelectedProxyServerIP extracts the server IP from the currently selected proxy.
func getSelectedProxyServerIP(config *configuration.Config) netip.Addr {
	selectedID := config.Selected.Proxy
	if selectedID == "" || selectedID == "DIRECT" {
		return netip.Addr{}
	}
	for _, p := range config.Proxy {
		id, _ := p["id"].(string)
		if id != selectedID {
			continue
		}
		server, _ := p["server"].(string)
		if server == "" {
			return netip.Addr{}
		}
		addr, err := netip.ParseAddr(server)
		if err != nil {
			return netip.Addr{}
		}
		return addr
	}
	return netip.Addr{}
}
