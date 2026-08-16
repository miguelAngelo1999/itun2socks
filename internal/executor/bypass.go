package executor

import (
	"net/netip"
	"strings"

	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// collectBypassCidrs gathers all IP prefixes that should bypass the TUN interface
// entirely at the routing table level. Traffic to these IPs never enters userspace.
//
// Sources (in order):
//  1. Explicit bypassCidrs from settings
//  2. The upstream proxy server's IP (auto-extracted from selected proxy config)
//  3. IP-CIDR rules with DIRECT policy from customized rules
//
// This function is called once at TUN startup and feeds into sing-tun's
// Inet4RouteExcludeAddress option.
func collectBypassCidrs() []netip.Prefix {
	var excludes []netip.Prefix

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
		if prefix.Addr().Is4() {
			excludes = append(excludes, prefix)
		}
	}

	// 2. Auto-extract ALL proxy server IPs so they always bypass TUN.
	// Without this, lux_core's own outbound connections to any proxy get captured
	// by TUN creating a routing loop.
	for _, p := range rawConfig.Proxy {
		server, _ := p["server"].(string)
		if server == "" {
			continue
		}
		addr, err := netip.ParseAddr(server)
		if err != nil || !addr.Is4() {
			continue
		}
		prefix := netip.PrefixFrom(addr, 32)
		excludes = append(excludes, prefix)
	}
	if len(rawConfig.Proxy) > 0 {
		log.Infoln(log.FormatLog(log.ExecutorPrefix, "bypass: auto-excluded %d proxy server IPs from TUN"), len(rawConfig.Proxy))
	}

	// 3. Extract IP-CIDR,x,DIRECT rules from customized rules
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

		if ruleType != string(constants.RuleIpCidr) {
			continue
		}
		if policy != string(constants.PolicyDirect) {
			continue
		}

		if !strings.Contains(payload, "/") {
			payload += "/32"
		}
		prefix, parseErr := netip.ParsePrefix(payload)
		if parseErr != nil {
			continue
		}
		if prefix.Addr().Is4() {
			excludes = append(excludes, prefix)
		}
	}

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
