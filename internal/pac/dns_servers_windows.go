//go:build windows

package pac

import (
	"net"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// discoverSystemDNS returns physical-adapter IPv4 DNS servers (private/LAN
// servers first, skipping Lux's TUN adapter and 10.255.0.2) plus any adapter
// DNS suffixes. This bypasses Windows Dnscache's refusal to forward single-label
// queries (like "wpad") to DNS when no primary/connection DNS suffix is set.
func discoverSystemDNS() (servers []string, suffixes []string) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return nil, nil
	}

	excludedTunMu.RLock()
	tunName := strings.ToLower(strings.TrimSpace(excludedTunIface))
	excludedTunMu.RUnlock()

	var privServers, pubServers []string
	seenSrv := make(map[string]bool)
	seenSfx := make(map[string]bool)

	for _, a := range adapters {
		if a == nil || a.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		if a.IfType == winipcfg.IfTypeSoftwareLoopback {
			continue
		}
		friendly := strings.ToLower(a.FriendlyName())
		desc := strings.ToLower(a.Description())
		if (tunName != "" && friendly == tunName) ||
			strings.HasPrefix(friendly, "utun") ||
			strings.Contains(desc, "itun2socks") ||
			strings.Contains(desc, "wintun") {
			continue
		}

		if sfx := strings.Trim(strings.TrimSpace(a.DNSSuffix()), "."); sfx != "" {
			low := strings.ToLower(sfx)
			if !seenSfx[low] {
				seenSfx[low] = true
				suffixes = append(suffixes, sfx)
			}
		}

		dnsList, err := a.LUID.DNS()
		if err != nil {
			continue
		}
		for _, addr := range dnsList {
			if !addr.Is4() {
				continue
			}
			ip := net.IP(addr.AsSlice())
			if ip == nil || ip.IsLoopback() || isExcludedIP(ip) {
				continue
			}
			s := addr.String()
			if seenSrv[s] {
				continue
			}
			seenSrv[s] = true
			if ip.IsPrivate() {
				privServers = append(privServers, s)
			} else {
				pubServers = append(pubServers, s)
			}
		}
	}

	servers = append(privServers, pubServers...)
	return servers, suffixes
}
