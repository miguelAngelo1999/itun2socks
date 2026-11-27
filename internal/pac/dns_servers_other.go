//go:build !windows && !darwin

package pac

import (
	"net"

	"github.com/igoogolx/itun2socks/pkg/clash/component/system_dns"
)

// discoverSystemDNS returns OS IPv4 DNS servers (private/LAN first, excluding
// loopback and Lux's TUN DNS 10.255.0.2).
func discoverSystemDNS() (servers []string, suffixes []string) {
	raw, err := system_dns.ResolveServers("")
	if err != nil {
		return nil, nil
	}
	var privServers, pubServers []string
	seen := make(map[string]bool)
	for _, s := range raw {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || isExcludedIP(ip) {
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		if ip.IsPrivate() {
			privServers = append(privServers, s)
		} else {
			pubServers = append(pubServers, s)
		}
	}
	return append(privServers, pubServers...), nil
}
