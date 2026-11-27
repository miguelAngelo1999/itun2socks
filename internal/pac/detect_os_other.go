//go:build !darwin && !windows

package pac

import "net"

// DetectOSProxyConfig collects DNS search domains and private DNS servers on
// non-macOS / non-Windows platforms.
func DetectOSProxyConfig() OSProxyConfig {
	var cfg OSProxyConfig
	servers, suffixes := discoverSystemDNS()
	for _, s := range suffixes {
		cfg.DNSSuffixes = appendUniqueStr(cfg.DNSSuffixes, s)
	}
	for _, srv := range servers {
		if ip := net.ParseIP(srv); ip != nil && ip.IsPrivate() && !isExcludedIP(ip) {
			cfg.PrivateDNS = appendUniqueStr(cfg.PrivateDNS, srv)
		}
	}
	return cfg
}
