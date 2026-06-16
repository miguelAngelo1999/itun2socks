//go:build windows

package routes

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// detectNetworkProxy discovers upstream proxies on Windows using three
// strategies, tried in order:
//
//  1. DHCP Option 252 (proxy auto-discovery URL) read from the registry key
//     populated by the DHCP client service.
//  2. WPAD DNS lookup (http://wpad/wpad.dat).
//  3. Manual proxy settings from Internet Settings registry.
func detectNetworkProxy() ProxyDetectResult {
	var proxies []DetectedProxy

	// ── 1. DHCP Option 252 ─────────────────────────────────────────────────
	if p := detectDHCPOption252(); p != nil {
		proxies = append(proxies, *p)
	}

	// ── 2. WPAD DNS fallback ────────────────────────────────────────────────
	if len(proxies) == 0 {
		if p := detectWPADDNS(); p != nil {
			proxies = append(proxies, *p)
		}
	}

	// ── 3. Internet Settings manual/PAC proxy ──────────────────────────────
	if p := detectInetSettingsProxy(); p != nil {
		proxies = append(proxies, *p)
	}

	return ProxyDetectResult{
		Detected: len(proxies) > 0,
		Proxies:  proxies,
	}
}

// ── DHCP Option 252 ───────────────────────────────────────────────────────────

// detectDHCPOption252 reads the WPAD/PAC URL delivered via DHCP Option 252.
//
// The Windows DHCP client stores received options under:
//
//	HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\DhcpInterfaceOptions
//
// Option 252 (0xFC) is the "Web Proxy Auto-Discovery" option. When present, its
// value is a UTF-8 / ASCII URL string.
//
// We also check the simpler "DhcpNameServer" adjacent key as a sanity check
// that we are reading the right adapter.
func detectDHCPOption252() *DetectedProxy {
	const baseKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, baseKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	for _, guid := range subkeys {
		subKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			baseKey+`\`+guid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		// Only look at adapters with a DHCP-assigned server (active DHCP lease)
		_, _, err = subKey.GetStringValue("DhcpNameServer")
		if err != nil {
			subKey.Close()
			continue
		}

		// DhcpInterfaceOptions is a REG_BINARY blob containing packed DHCP options.
		blob, _, err := subKey.GetBinaryValue("DhcpInterfaceOptions")
		subKey.Close()
		if err != nil || len(blob) == 0 {
			continue
		}

		url := parseDHCPOption252FromBlob(blob)
		if url == "" {
			continue
		}
		return parsePACURL(url, "dhcp_option252")
	}
	return nil
}

// parseDHCPOption252FromBlob walks the DhcpInterfaceOptions binary blob and
// extracts the value for option 252 (0xFC).
//
// The blob format used by the Windows DHCP client for DhcpInterfaceOptions is:
//
//	[option_code: uint32 LE][unknown: uint32 LE][length: uint32 LE][data: length bytes][padding to 4-byte boundary]...
//
// This is undocumented but consistent across Windows 7–11.
func parseDHCPOption252FromBlob(blob []byte) string {
	const option252 = 0xFC
	i := 0
	for i+12 <= len(blob) {
		// Read option code (4 bytes LE)
		code := uint32(blob[i]) | uint32(blob[i+1])<<8 | uint32(blob[i+2])<<16 | uint32(blob[i+3])<<24
		// Skip 4 bytes of unknown field
		length := uint32(blob[i+8]) | uint32(blob[i+9])<<8 | uint32(blob[i+10])<<16 | uint32(blob[i+11])<<24
		i += 12
		if int(length) > len(blob)-i {
			break
		}
		data := blob[i : i+int(length)]
		// Advance past data, aligned to 4 bytes
		advance := int(length)
		if advance%4 != 0 {
			advance += 4 - (advance % 4)
		}
		i += advance

		if code == option252 {
			// Value is a null-terminated ASCII string
			s := strings.TrimRight(string(data), "\x00")
			if s != "" {
				return s
			}
		}
	}
	return ""
}

// ── WPAD DNS fallback ─────────────────────────────────────────────────────────

// detectWPADDNS tries to resolve "wpad" via DNS and fetches /wpad.dat.
func detectWPADDNS() *DetectedProxy {
	addrs, err := net.LookupHost("wpad")
	if err != nil || len(addrs) == 0 {
		return nil
	}
	wpadURL := fmt.Sprintf("http://%s/wpad.dat", addrs[0])
	return parsePACURL(wpadURL, "wpad_dns")
}

// ── Internet Settings manual / PAC proxy ──────────────────────────────────────

// detectInetSettingsProxy reads the WinInet proxy settings from the registry.
// This covers:
//   - A manually configured ProxyServer
//   - An AutoConfigURL (PAC file)
func detectInetSettingsProxy() *DetectedProxy {
	const keyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()

	// Check for PAC/AutoConfig URL first
	autoURL, _, err := key.GetStringValue("AutoConfigURL")
	if err == nil && autoURL != "" {
		return parsePACURL(autoURL, "pac")
	}

	// Check for manual proxy
	enabled, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil || enabled == 0 {
		return nil
	}
	proxyServer, _, err := key.GetStringValue("ProxyServer")
	if err != nil || proxyServer == "" {
		return nil
	}

	host, port := splitProxyServer(proxyServer)
	if host == "" {
		return nil
	}
	d := &DetectedProxy{
		Source: "manual",
		Host:   host,
		Port:   port,
	}
	probeProxy(d)
	return d
}

// splitProxyServer handles the various formats used by WinInet:
//   - "host:port"          — plain HTTP proxy
//   - "socks=host:port"    — SOCKS proxy
//   - "http=h:p;https=h:p" — per-protocol list
func splitProxyServer(s string) (host, port string) {
	// Per-protocol: pick http= first, fall back to first entry
	if strings.Contains(s, "=") {
		for _, part := range strings.Split(s, ";") {
			part = strings.TrimSpace(part)
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				h, p, err := net.SplitHostPort(kv[1])
				if err == nil {
					return h, p
				}
			}
		}
		return "", ""
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", ""
	}
	return h, p
}

// ── PAC file fetching & parsing ───────────────────────────────────────────────

// parsePACURL fetches a PAC file at the given URL, extracts the first PROXY
// directive, and probes it for connectivity / 407 auth.
func parsePACURL(pacURL string, source string) *DetectedProxy {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(pacURL) //nolint:noctx
	if err != nil {
		return &DetectedProxy{
			Source: source,
			PacURL: pacURL,
			Error:  fmt.Sprintf("fetch PAC failed: %v", err),
		}
	}
	defer resp.Body.Close()

	buf := make([]byte, 32*1024)
	n, _ := resp.Body.Read(buf)
	pac := string(buf[:n])

	host, port := extractFirstProxyFromPAC(pac)
	if host == "" {
		return &DetectedProxy{
			Source: source,
			PacURL: pacURL,
			Error:  "no PROXY directive found in PAC",
		}
	}
	d := &DetectedProxy{
		Source: source,
		Host:   host,
		Port:   port,
		PacURL: pacURL,
	}
	probeProxy(d)
	return d
}

// extractFirstProxyFromPAC uses a simple regex to find the first
// "PROXY host:port" directive in PAC JavaScript text.
func extractFirstProxyFromPAC(pac string) (host, port string) {
	re := regexp.MustCompile(`(?i)\bPROXY\s+([\w.\-]+):(\d+)`)
	if m := re.FindStringSubmatch(pac); len(m) == 3 {
		return m[1], m[2]
	}
	return "", ""
}

// ── Proxy probe ───────────────────────────────────────────────────────────────

// probeProxy dials the proxy and sends an HTTP CONNECT to detect 407 auth
// requirements.
func probeProxy(d *DetectedProxy) {
	if d.Host == "" || d.Port == "" {
		return
	}
	addr := net.JoinHostPort(d.Host, d.Port)
	conn, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		d.Error = fmt.Sprintf("probe dial failed: %v", err)
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	_, err = fmt.Fprintf(conn, "CONNECT www.msftconnecttest.com:443 HTTP/1.1\r\nHost: www.msftconnecttest.com:443\r\n\r\n")
	if err != nil {
		return
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.Contains(resp, "407") {
		d.RequiresAuth = true
	}
}


