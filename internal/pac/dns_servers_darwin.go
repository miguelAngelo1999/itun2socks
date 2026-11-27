//go:build darwin

package pac

import (
	"net"
	"os/exec"
	"strings"

	"github.com/igoogolx/itun2socks/pkg/clash/component/system_dns"
)

// discoverSystemDNS returns all reachable IPv4 DNS servers on macOS (private/
// LAN/VPN servers first, excluding loopback and Lux's TUN DNS 10.255.0.2) plus
// search domains. Parsing `scutil --dns` ensures supplemental VPN DNS servers
// and secondary physical interfaces (e.g. corporate Wi-Fi alongside Ethernet)
// are queried when resolving single-label intranet names like "wpad".
func discoverSystemDNS() (servers []string, suffixes []string) {
	var privServers, pubServers []string
	seenSrv := make(map[string]bool)
	seenSfx := make(map[string]bool)

	addServer := func(raw string) {
		s := strings.TrimSpace(raw)
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || isExcludedIP(ip) {
			return
		}
		if seenSrv[s] {
			return
		}
		seenSrv[s] = true
		if ip.IsPrivate() {
			privServers = append(privServers, s)
		} else {
			pubServers = append(pubServers, s)
		}
	}

	addSuffix := func(raw string) {
		d := strings.Trim(strings.TrimSpace(raw), ".")
		if d == "" {
			return
		}
		low := strings.ToLower(d)
		if low == "local" || strings.HasSuffix(low, ".arpa") {
			return
		}
		if seenSfx[low] {
			return
		}
		seenSfx[low] = true
		suffixes = append(suffixes, d)
	}

	// 1. Parse `scutil --dns` for ALL active resolvers (including VPN/supplemental).
	if out, err := exec.Command("scutil", "--dns").Output(); err == nil {
		// Split into resolver blocks; stop before "DNS configuration (for scoped queries)"
		// duplicates or process all blocks while skipping mdns / Lux's own TUN.
		blocks := strings.Split(string(out), "\nresolver #")
		for _, blk := range blocks[1:] {
			isMDNS := false
			isExcluded := false
			var blkServers []string
			var blkSuffixes []string

			for _, line := range strings.Split(blk, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "options") && strings.Contains(trimmed, "mdns") {
					isMDNS = true
					break
				}
				if strings.HasPrefix(trimmed, "if_index") {
					if idx := strings.Index(trimmed, "("); idx >= 0 {
						if end := strings.Index(trimmed[idx:], ")"); end > 1 {
							ifaceName := strings.TrimSpace(trimmed[idx+1 : idx+end])
							if IsExcludedTunIface(ifaceName) {
								isExcluded = true
								break
							}
						}
					}
				}
				if strings.HasPrefix(trimmed, "nameserver[") {
					if parts := strings.SplitN(trimmed, ":", 2); len(parts) == 2 {
						blkServers = append(blkServers, strings.TrimSpace(parts[1]))
					}
				}
				if strings.HasPrefix(trimmed, "search domain[") || strings.HasPrefix(trimmed, "domain ") || strings.HasPrefix(trimmed, "domain:") {
					if parts := strings.SplitN(trimmed, ":", 2); len(parts) == 2 {
						blkSuffixes = append(blkSuffixes, strings.TrimSpace(parts[1]))
					}
				}
			}
			if isMDNS || isExcluded {
				continue
			}
			for _, s := range blkServers {
				addServer(s)
			}
			for _, d := range blkSuffixes {
				addSuffix(d)
			}
		}
	}

	// 2. Also include primary service DNS from system_dns as fallback.
	if raw, err := system_dns.ResolveServers(""); err == nil {
		for _, s := range raw {
			addServer(s)
		}
	}

	// 3. Also check DHCP domain_name_server on active physical en* interfaces
	// (e.g. corporate Wi-Fi en0 when another interface has higher service order).
	if ifaces, err := net.Interfaces(); err == nil {
		for _, nif := range ifaces {
			if nif.Flags&net.FlagUp == 0 || !strings.HasPrefix(nif.Name, "en") {
				continue
			}
			out, err := exec.Command("ipconfig", "getpacket", nif.Name).Output()
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "domain_name_server (ip_mult):") {
					if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
						raw := strings.Trim(strings.TrimSpace(parts[1]), "{}")
						for _, tok := range strings.Split(raw, ",") {
							addServer(tok)
						}
					}
				}
			}
		}
	}

	return append(privServers, pubServers...), suffixes
}
