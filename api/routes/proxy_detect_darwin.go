//go:build darwin

package routes

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// detectNetworkProxy discovers the upstream proxy on macOS using scutil and
// networksetup. It also attempts to parse PAC files returned by WPAD.
func detectNetworkProxy() ProxyDetectResult {
	var proxies []DetectedProxy

	// ── 1. Check system web proxy via networksetup ─────────────────────────
	if p := detectNetworkSetupProxy("webproxy", "http"); p != nil {
		proxies = append(proxies, *p)
	}
	if p := detectNetworkSetupProxy("securewebproxy", "https"); p != nil {
		proxies = append(proxies, *p)
	}
	if p := detectNetworkSetupProxy("socksfirewallproxy", "socks"); p != nil {
		proxies = append(proxies, *p)
	}

	// ── 2. Check for auto-proxy (PAC) URL via networksetup ─────────────────
	if p := detectAutoProxyURL(); p != nil {
		proxies = append(proxies, *p)
	}

	// ── 3. Check WPAD via scutil ────────────────────────────────────────────
	if p := detectWPADViaSCUtil(); p != nil {
		proxies = append(proxies, *p)
	}

	return ProxyDetectResult{
		Detected: len(proxies) > 0,
		Proxies:  proxies,
	}
}

// detectNetworkSetupProxy queries a named proxy type on the active interface.
func detectNetworkSetupProxy(proxyType, _ string) *DetectedProxy {
	iface, err := getMacActiveInterface()
	if err != nil || iface == "" {
		return nil
	}
	cmd := fmt.Sprintf("get%s", proxyType)
	out, err := exec.Command("networksetup", "-"+cmd, iface).Output()
	if err != nil {
		return nil
	}
	settings := parseMacProxyOutput(string(out))
	if settings == nil || !settings.enabled || settings.host == "" {
		return nil
	}
	d := &DetectedProxy{
		Source: "manual",
		Host:   settings.host,
		Port:   settings.port,
	}
	probeProxy(d)
	return d
}

// detectAutoProxyURL reads any configured PAC URL from networksetup and
// attempts to parse it for a concrete host:port.
func detectAutoProxyURL() *DetectedProxy {
	iface, err := getMacActiveInterface()
	if err != nil || iface == "" {
		return nil
	}
	out, err := exec.Command("networksetup", "-getautoproxyurl", iface).Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(out), "\n")
	var pacURL string
	var enabled bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "URL:") {
			pacURL = strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
		}
		if strings.HasPrefix(line, "Enabled:") && strings.Contains(line, "Yes") {
			enabled = true
		}
	}
	if !enabled || pacURL == "" || pacURL == "(null)" {
		return nil
	}
	return parsePACURL(pacURL, "pac")
}

// detectWPADViaSCUtil checks for a WPAD proxy URL via scutil --proxy.
func detectWPADViaSCUtil() *DetectedProxy {
	out, err := exec.Command("scutil", "--proxy").Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(out), "\n")
	var wpadURL string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// scutil reports: ProxyAutoConfigURLString : http://wpad/wpad.dat
		if strings.HasPrefix(line, "ProxyAutoConfigURLString") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				wpadURL = strings.TrimSpace(parts[1])
			}
		}
		// Also check ProxyAutoDiscoveryEnable
	}
	if wpadURL == "" {
		return nil
	}
	return parsePACURL(wpadURL, "wpad_dns")
}

// getMacActiveInterface returns the primary network interface name.
func getMacActiveInterface() (string, error) {
	out, err := exec.Command("networksetup", "-listnetworkserviceorder").Output()
	if err != nil {
		return "", err
	}
	inetOut, err := exec.Command("route", "get", "default").Output()
	if err != nil {
		return "", err
	}
	// Extract interface device (e.g. en0) from `route get default`
	var dev string
	for _, line := range strings.Split(string(inetOut), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				dev = fields[1]
				break
			}
		}
	}
	if dev == "" {
		return "", fmt.Errorf("no default interface")
	}
	// Find the service name that maps to this device
	re := regexp.MustCompile(`\(Hardware Port: ([^,]+), Device: ([^)]+)\)`)
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if matches := re.FindStringSubmatch(line); len(matches) == 3 {
			if strings.TrimSpace(matches[2]) == dev {
				return matches[1], nil
			}
		}
	}
	return dev, nil
}

// macProxySettings holds parsed output from networksetup -get*proxy.
type macProxySettings struct {
	host    string
	port    string
	enabled bool
}

func parseMacProxyOutput(output string) *macProxySettings {
	s := &macProxySettings{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Server:"):
			s.host = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		case strings.HasPrefix(line, "Port:"):
			s.port = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
		case strings.HasPrefix(line, "Enabled:"):
			s.enabled = strings.Contains(line, "Yes")
		}
	}
	if s.host == "" {
		return nil
	}
	return s
}

// parsePACURL fetches a PAC URL, extracts the first PROXY directive and probes
// the result. The source parameter is stored in DetectedProxy.Source.
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
	// Matches:  return "PROXY host:port; ..."  or  "PROXY host:port"
	re := regexp.MustCompile(`(?i)PROXY\s+([\w.\-]+):(\d+)`)
	if m := re.FindStringSubmatch(pac); len(m) == 3 {
		return m[1], m[2]
	}
	return "", ""
}

// probeProxy sends a CONNECT / HTTP request through the detected proxy to
// check connectivity and 407 auth requirements.
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

	// Send a minimal HTTP CONNECT to detect 407
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	_, err = fmt.Fprintf(conn, "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n")
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
