package pac

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

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

	for _, srv := range servers {
		addr := srv
		srvIPStr := srv
		if h, _, err := net.SplitHostPort(addr); err == nil {
			srvIPStr = h
		} else {
			addr = net.JoinHostPort(addr, "53")
		}
		// Single-label names (e.g. "wpad", "intranet") only exist on local/LAN
		// DNS servers, never on public resolvers like 1.1.1.1 or 8.8.8.8.
		if singleLabel {
			if sip := net.ParseIP(srvIPStr); sip != nil && !sip.IsPrivate() && !sip.IsLoopback() {
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

			resp, _, err := client.ExchangeContext(ctx, msg, addr)
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
