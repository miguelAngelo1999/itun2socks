package routes

import (
	"context"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/go-chi/render"
)

// DetectedProxy holds the result of a network proxy auto-detection probe.
type DetectedProxy struct {
	Found     bool   `json:"found"`
	Host      string `json:"host"`
	Port      string `json:"port"`
	Scheme    string `json:"scheme"`
	NeedsAuth bool   `json:"needsAuth"`
	Source    string `json:"source"`
}

// detectNetworkProxy probes the current network for an upstream proxy.
func detectNetworkProxy() DetectedProxy {
	if runtime.GOOS == "darwin" {
		// Step 1: DHCP Option 252 — read from all active interfaces
		if d := probeDhcpOption252(); d.Found {
			return d
		}
		// Step 2: System proxy (skip Lux's own 127.0.0.1)
		if d := probeScutil(); d.Found {
			return d
		}
		// Step 3: DNS WPAD via real DHCP DNS servers
		if d := probeWpadViaDhcpDns(); d.Found {
			return d
		}
	} else if runtime.GOOS == "windows" {
		// Step 1: Internet Explorer/Edge system proxy from registry
		if d := probeWindowsRegistry(); d.Found {
			return d
		}
		// Step 2: WinHTTP proxy (set by GPO/DHCP, independent of IE settings)
		if d := probeNetshWinhttp(); d.Found {
			return d
		}
		// Step 3: WPAD via DNS
		if d := probeWpadViaDhcpDns(); d.Found {
			return d
		}
	}
	return DetectedProxy{Found: false}
}

// probeDhcpOption252 reads the WPAD PAC URL from DHCP option 252
// using `ipconfig getpacket <interface>` on macOS.
func probeDhcpOption252() DetectedProxy {
	// Get active network interfaces
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		// Skip loopback and inactive interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if !strings.HasPrefix(iface.Name, "en") {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, "ipconfig", "getpacket", iface.Name).Output()
		cancel()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			// Look for: proxy_auto_discovery_url (string): http://...
			if strings.Contains(line, "proxy_auto_discovery_url") {
				parts := strings.SplitN(line, "): ", 2)
				if len(parts) == 2 {
					pacURL := strings.TrimSpace(parts[1])
					if pacURL != "" {
						if d := fetchAndParsePac(pacURL, "dhcp-252"); d.Found {
							return d
						}
					}
				}
			}
		}
	}
	return DetectedProxy{Found: false}
}

// fetchAndParsePac fetches a PAC file URL and extracts the proxy address.
// Uses a direct connection (no proxy/TUN).
func fetchAndParsePac(pacURL, source string) DetectedProxy {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	resp, err := client.Get(pacURL)
	if err != nil {
		return DetectedProxy{Found: false}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return DetectedProxy{Found: false}
	}
	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	host, port := parsePacProxy(string(buf[:n]))
	if host != "" {
		return DetectedProxy{Found: true, Host: host, Port: port, Scheme: "http", Source: source}
	}
	return DetectedProxy{Found: false}
}

// probeScutil reads macOS system proxy (skips Lux's 127.0.0.1).
func probeScutil() DetectedProxy {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "scutil", "--proxy").Output()
	if err != nil {
		return DetectedProxy{Found: false}
	}
	settings := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " : ", 2)
		if len(parts) == 2 {
			settings[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	for _, prefix := range []string{"HTTP", "HTTPS"} {
		if settings[prefix+"Enable"] == "1" {
			host := settings[prefix+"Proxy"]
			port := settings[prefix+"Port"]
			if host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1" {
				continue
			}
			return DetectedProxy{Found: true, Host: host, Port: port, Scheme: strings.ToLower(prefix), Source: "scutil"}
		}
	}
	return DetectedProxy{Found: false}
}

// probeWpadViaDhcpDns resolves "wpad" using real DHCP DNS servers
// (skipping Lux's fake-IP range) and fetches wpad.dat.
func probeWpadViaDhcpDns() DetectedProxy {
	dhcpDns := getDhcpDnsServers()
	if len(dhcpDns) == 0 {
		return DetectedProxy{Found: false}
	}
	for _, dnsServer := range dhcpDns {
		if !strings.Contains(dnsServer, ":") {
			dnsServer += ":53"
		}
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		addrs, err := resolver.LookupHost(ctx, "wpad")
		cancel()
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, ip := range addrs {
			if strings.HasPrefix(ip, "198.18.") || strings.HasPrefix(ip, "198.19.") {
				continue
			}
			pacURL := "http://" + ip + "/wpad.dat"
			if d := fetchAndParsePac(pacURL, "wpad-dns"); d.Found {
				return d
			}
		}
	}
	return DetectedProxy{Found: false}
}

// getDhcpDnsServers returns real (non-fake-IP) DNS servers from scutil --dns.
// macOS only — Windows has its own implementation in proxy_detect_dns_windows.go.
//
func getDhcpDnsServersDarwin() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil {
		return nil
	}
	var servers []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver[") {
			parts := strings.SplitN(line, " : ", 2)
			if len(parts) == 2 {
				srv := strings.TrimSpace(parts[1])
				if strings.HasPrefix(srv, "198.18.") || strings.HasPrefix(srv, "198.19.") ||
					srv == "127.0.0.1" || srv == "::1" {
					continue
				}
				if !seen[srv] {
					seen[srv] = true
					servers = append(servers, srv)
				}
			}
		}
	}
	return servers
}

// parsePacProxy extracts the first "PROXY host:port" from a PAC file.
func parsePacProxy(pac string) (host, port string) {
	for _, prefix := range []string{"PROXY ", "proxy "} {
		idx := strings.Index(pac, prefix)
		if idx < 0 {
			continue
		}
		rest := pac[idx+len(prefix):]
		if end := strings.IndexAny(rest, " \t\n\r;\"'"); end > 0 {
			rest = rest[:end]
		}
		rest = strings.TrimSpace(rest)
		if strings.Contains(rest, ":") {
			parts := strings.SplitN(rest, ":", 2)
			h := strings.TrimSpace(parts[0])
			p := strings.TrimSpace(parts[1])
			// Skip DIRECT entries
			if strings.EqualFold(h, "DIRECT") {
				continue
			}
			return h, p
		}
	}
	return "", ""
}

// testProxyAuth checks if proxy returns 407.
func testProxyAuth(host, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("CONNECT detecttest.lux.internal:443 HTTP/1.1\r\nHost: detecttest.lux.internal:443\r\n\r\n"))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return false
	}
	return strings.Contains(string(buf[:n]), "407")
}

// GET /proxies/detect
func detectProxy(w http.ResponseWriter, r *http.Request) {
	result := detectNetworkProxy()
	if result.Found && result.Port != "" {
		result.NeedsAuth = testProxyAuth(result.Host, result.Port)
	}
	render.JSON(w, r, result)
}

