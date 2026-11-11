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
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		prefix, parseErr := netip.ParsePrefix(cidr)
		if parseErr != nil {
			log.Warnln(log.FormatLog(log.ExecutorPrefix, "bypass: invalid CIDR %q: %v"), cidr, parseErr)
			continue
		}
		if prefix.Addr().Is4() && !seen[prefix] {
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

	// 5. Extract IP-CIDR,x,DIRECT rules from customized rules
	for _, raw := range rawConfig.Rules {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.SplitN(raw, ",", 4)
		if len(parts) < 3 {
			continue
		}
		ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))
		payload := strings.TrimSpace(parts[1])
		policy := strings.ToUpper(strings.TrimSpace(parts[2]))

		if ruleType != string(constants.RuleIpCidr) || policy != string(constants.PolicyDirect) {
			continue
		}

		if !strings.Contains(payload, "/") {
			payload += "/32"
		}
		prefix, parseErr := netip.ParsePrefix(payload)
		if parseErr != nil {
			continue
		}
		if prefix.Addr().Is4() && !seen[prefix] {
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
