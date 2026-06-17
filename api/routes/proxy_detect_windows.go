//go:build windows

package routes

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWinHTTP = windows.NewLazySystemDLL("winhttp.dll")
	modKernel  = windows.NewLazySystemDLL("kernel32.dll")

	procWinHttpOpen                      = modWinHTTP.NewProc("WinHttpOpen")
	procWinHttpCloseHandle               = modWinHTTP.NewProc("WinHttpCloseHandle")
	procWinHttpDetectAutoProxyConfigUrl  = modWinHTTP.NewProc("WinHttpDetectAutoProxyConfigUrl")
	procWinHttpGetIEProxyConfigForCurUsr = modWinHTTP.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	procGlobalFree                       = modKernel.NewProc("GlobalFree")
)

// WINHTTP constants
const (
	winHTTPAccessTypeNoProxy         = 1
	winHTTPAutoDetectTypeDHCP        = 0x00000001
	winHTTPAutoDetectTypeDNSA        = 0x00000002
	winHTTPFlagAsync                 = 0x10000000
)

// WINHTTP_CURRENT_USER_IE_PROXY_CONFIG mirrors the WinAPI struct.
// All string fields are pointers to wide-char strings allocated by WinHTTP —
// caller must free them with GlobalFree.
type winHTTPCurrentUserIEProxyConfig struct {
	fAutoDetect       uint32
	lpszAutoConfigUrl uintptr // LPWSTR
	lpszProxy         uintptr // LPWSTR
	lpszProxyBypass   uintptr // LPWSTR
}

// detectNetworkProxy discovers upstream proxies on Windows using the WinHTTP
// auto-proxy API — the same mechanism used by Internet Explorer / Edge.
//
// Detection order (mirrors what Windows itself does for "Automatically detect
// settings"):
//
//  1. WinHttpDetectAutoProxyConfigUrl — queries DHCP (option 252) then DNS
//     (wpad.<domain>) to discover a PAC/WPAD URL.
//  2. WinHttpGetIEProxyConfigForCurrentUser — reads the user's Internet
//     Options (auto-config URL or manual proxy).
//
// We intentionally do NOT read the raw WinInet ProxyServer registry value,
// because lux itself writes 127.0.0.1:1090 there while running.
func detectNetworkProxy() ProxyDetectResult {
	var proxies []DetectedProxy

	// ── 1. OS auto-detection via DHCP + DNS ───────────────────────────────
	if p := detectViaWinHTTPAutoDetect(); p != nil {
		proxies = append(proxies, *p)
	}

	// ── 2. IE/Edge proxy config (AutoConfigURL only — skip manual proxy) ──
	if len(proxies) == 0 {
		if p := detectViaIEProxyConfig(); p != nil {
			proxies = append(proxies, *p)
		}
	}

	return ProxyDetectResult{
		Detected: len(proxies) > 0,
		Proxies:  proxies,
	}
}

// detectViaWinHTTPAutoDetect calls WinHttpDetectAutoProxyConfigUrl which
// performs DHCP option-252 and DNS wpad.<domain> discovery and returns the
// PAC URL if one is found on the network.
func detectViaWinHTTPAutoDetect() *DetectedProxy {
	// Open a WinHTTP session handle (required before any WinHTTP call)
	hSession, _, _ := procWinHttpOpen.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("lux/proxy-detect"))),
		uintptr(winHTTPAccessTypeNoProxy),
		0, 0, 0,
	)
	if hSession == 0 {
		return nil
	}
	defer procWinHttpCloseHandle.Call(hSession)

	// dwAutoDetectFlags: try DHCP first, fall back to DNS
	const flags = winHTTPAutoDetectTypeDHCP | winHTTPAutoDetectTypeDNSA
	var pURL uintptr // LPWSTR — allocated by WinHTTP, freed by us
	ret, _, _ := procWinHttpDetectAutoProxyConfigUrl.Call(
		uintptr(flags),
		uintptr(unsafe.Pointer(&pURL)),
	)
	if ret == 0 || pURL == 0 {
		// No WPAD/PAC URL found on this network — that's normal
		return nil
	}
	// Convert the UTF-16 string and free the memory
	pacURL := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(pURL)))
	procGlobalFree.Call(pURL)

	if pacURL == "" {
		return nil
	}
	return parsePACURL(pacURL, "dhcp_wpad")
}

// detectViaIEProxyConfig reads the current user's Internet Options proxy
// config (the same data shown in Control Panel → Internet Options → Connections
// → LAN Settings). We only act on an AutoConfigURL (PAC file) — we skip the
// manual ProxyServer value because lux writes itself there.
func detectViaIEProxyConfig() *DetectedProxy {
	var cfg winHTTPCurrentUserIEProxyConfig
	ret, _, _ := procWinHttpGetIEProxyConfigForCurUsr.Call(
		uintptr(unsafe.Pointer(&cfg)),
	)
	if ret == 0 {
		return nil
	}
	defer func() {
		if cfg.lpszAutoConfigUrl != 0 {
			procGlobalFree.Call(cfg.lpszAutoConfigUrl)
		}
		if cfg.lpszProxy != 0 {
			procGlobalFree.Call(cfg.lpszProxy)
		}
		if cfg.lpszProxyBypass != 0 {
			procGlobalFree.Call(cfg.lpszProxyBypass)
		}
	}()

	// Prefer AutoConfigURL (PAC file) — skip manual proxy (likely lux itself)
	if cfg.lpszAutoConfigUrl != 0 {
		autoURL := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(cfg.lpszAutoConfigUrl)))
		if autoURL != "" {
			return parsePACURL(autoURL, "pac")
		}
	}

	// fAutoDetect=1 means "Automatically detect settings" is ticked but
	// WinHttpDetectAutoProxyConfigUrl already covered that above — skip.

	return nil
}

// ── PAC file fetching & parsing ───────────────────────────────────────────────

// parsePACURL fetches a PAC/WPAD file, extracts the first non-loopback PROXY
// directive, probes for 407 auth, and returns a DetectedProxy.
func parsePACURL(pacURL string, source string) *DetectedProxy {
	// Use a transport that bypasses the system proxy — the system proxy at this
	// point may already be set to lux itself (127.0.0.1), which would cause
	// the PAC fetch to loop or fail.
	transport := &http.Transport{
		Proxy: nil, // explicit no-proxy
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}
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
	// Don't report lux itself (127.x / localhost) as an upstream proxy
	if isLoopback(host) {
		return nil
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

// extractFirstProxyFromPAC finds the first "PROXY host:port" directive in PAC
// JavaScript. Handles both bare (PROXY host:port) and quoted ("PROXY host:port")
// forms as produced by various PAC generators.
func extractFirstProxyFromPAC(pac string) (host, port string) {
	// Matches PROXY keyword optionally preceded/followed by quotes or spaces
	re := regexp.MustCompile(`(?i)PROXY\s+([\w.\-]+):(\d+)`)
	if m := re.FindStringSubmatch(pac); len(m) == 3 {
		return m[1], m[2]
	}
	return "", ""
}

// isLoopback returns true for 127.x.x.x, ::1, and "localhost".
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// probeProxy dials the proxy and sends an HTTP CONNECT to detect 407 auth.
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
	// Use a target that is NOT typically whitelisted by proxy ACLs.
	// Many proxies whitelist captive portal domains; use a generic target instead.
	_, err = fmt.Fprintf(conn, "CONNECT google.com:443 HTTP/1.1\r\nHost: google.com:443\r\n\r\n")
	if err != nil {
		return
	}
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "407") {
		d.RequiresAuth = true
	}
}
