package pac

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	D "github.com/miekg/dns"
)

var (
	systemDNSProviderMu sync.RWMutex
	systemDNSProvider   = discoverSystemDNS
)

// querySystemDNS sends a direct DNS A query to physical OS DNS servers (LAN/
// private servers first, e.g. 10.60.0.1:53).
//
// Why this is needed:
//   - On Windows, net.DefaultResolver uses Win32 GetAddrInfoW (Dnscache), which
//     refuses to send single-label queries like "wpad" to the configured DNS
//     server whenever Primary/Connection DNS Suffix is empty.
//   - In System mode or when disconnected, localLookup is not registered.
//   - Querying the physical adapter's DNS server directly resolves single-label
//     intranet hostnames (e.g. "wpad" -> 10.60.1.1) in ~1-2ms across every mode.
func querySystemDNS(ctx context.Context, host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	systemDNSProviderMu.RLock()
	provider := systemDNSProvider
	systemDNSProviderMu.RUnlock()

	servers, suffixes := provider()
	if len(servers) == 0 {
		return ""
	}

	singleLabel := !strings.Contains(host, ".")

	// Build candidate FQDNs: always try exact host first ("wpad."), then append
	// any adapter DNS search suffixes for single-label hostnames.
	candidates := []string{D.Fqdn(host)}
	if singleLabel {
		for _, sfx := range suffixes {
			sfx = strings.Trim(strings.TrimSpace(sfx), ".")
			if sfx != "" {
				candidates = append(candidates, D.Fqdn(host+"."+sfx))
			}
		}
	}

	client := &D.Client{
		Net:     "udp",
		Timeout: 350 * time.Millisecond,
	}

	defIface := dialer.DefaultInterface.Load()
	if IsExcludedTunIface(defIface) {
		defIface = ""
	}

	for _, srv := range servers {
		addr := srv
		srvIPStr := srv
		if h, _, err := net.SplitHostPort(addr); err == nil {
			srvIPStr = h
		} else {
			addr = net.JoinHostPort(addr, "53")
		}
		srvIP := net.ParseIP(srvIPStr)
		// Single-label names (e.g. "wpad", "intranet") only exist on local/LAN
		// DNS servers, never on public resolvers like 1.1.1.1 or 8.8.8.8.
		if singleLabel {
			if srvIP != nil && !srvIP.IsPrivate() && !srvIP.IsLoopback() {
				continue
			}
		}
		for _, qname := range candidates {
			if ctx.Err() != nil {
				return ""
			}
			msg := new(D.Msg)
			msg.SetQuestion(qname, D.TypeA)
			msg.RecursionDesired = true

			var (
				resp *D.Msg
				err  error
			)
			// When TUN is active and the discovered DHCP DNS server is public
			// (e.g. 8.8.8.8), bind UDP/53 to the physical interface so the query
			// bypasses TUN and Fake-IP.
			if defIface != "" && srvIP != nil && !srvIP.IsLoopback() && !srvIP.IsPrivate() {
				rawConn, dialErr := dialer.DialContext(ctx, "udp4", addr, dialer.WithInterface(defIface))
				if dialErr != nil {
					continue
				}
				dConn := &D.Conn{Conn: rawConn}
				resp, _, err = client.ExchangeWithConnContext(ctx, msg, dConn)
				_ = dConn.Close()
			} else {
				resp, _, err = client.ExchangeContext(ctx, msg, addr)
			}
			if err != nil || resp == nil {
				continue
			}
			for _, ans := range resp.Answer {
				if a, ok := ans.(*D.A); ok && a.A != nil {
					ip4 := a.A.To4()
					if ip4 != nil && !isExcludedIP(ip4) && !ip4.IsLoopback() {
						return ip4.String()
					}
				}
			}
		}
	}
	return ""
}

// LookupFreshIPv4 resolves host to an IPv4 address WITHOUT using the long-lived
// PAC DNS cache and WITHOUT accepting Fake-IPs (198.18.0.0/15, 10.255.0.0/16).
func LookupFreshIPv4(ctx context.Context, host string) string {
	return LookupFreshIPv4Strict(ctx, host, false)
}

// LookupFreshIPv4Strict is LookupFreshIPv4 with an explicit skipOSResolver flag.
// When TUN / DNS hijack is active, callers pass skipOSResolver=true so resolution
// never falls back to net.DefaultResolver (which queries Lux's hijacked 10.255.0.2).
func LookupFreshIPv4Strict(ctx context.Context, host string, skipOSResolver bool) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil && !isExcludedIP(ip4) {
			return ip4.String()
		}
		return ""
	}
	if strings.EqualFold(host, "localhost") {
		return "127.0.0.1"
	}

	// 1. Direct uncached query to physical LAN / DHCP DNS servers first.
	sysCtx, sysCancel := context.WithTimeout(ctx, 800*time.Millisecond)
	ipStr := querySystemDNS(sysCtx, host)
	sysCancel()
	if ipStr != "" {
		return ipStr
	}

	// 2. Lux's configured non-Fake-IP local DNS resolver (if TUN is running).
	localLookupMu.RLock()
	fn := localLookup
	localLookupMu.RUnlock()
	if fn != nil {
		localCtx, localCancel := context.WithTimeout(ctx, 700*time.Millisecond)
		addrs, err := fn(localCtx, host)
		localCancel()
		if err == nil {
			for _, a := range addrs {
				if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && !isExcludedIP(ip) && !ip.IsLoopback() {
					return ip.To4().String()
				}
			}
		}
	}

	// 3. Fallback to OS resolver only when TUN/DNS hijack is NOT active.
	if skipOSResolver {
		return ""
	}
	osCtx, osCancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer osCancel()
	if ips, err := net.DefaultResolver.LookupIP(osCtx, "ip4", host); err == nil {
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil && !isExcludedIP(ip4) && !ip4.IsLoopback() {
				return ip4.String()
			}
		}
	}

	return ""
}
