package routes

// net_probe.go — low-level network probes for the auto-switch & captive-portal controller.
//
// All probes run INSIDE lux_core using TUN-exempt sockets and uncached real LAN
// DNS (never Fake-IP and never HTTP_PROXY env vars). Flutter sockets are NOT
// exempt — probing from Dart while proxy_all is active gives wrong answers.
//
// Two probe kinds:
//   probeProxy  — full HTTP CONNECT through the proxy to captive.apple.com:443.
//                 200 = verify TLS handshake through the tunnel (rejects fake
//                 plaintext HTTP responders while accepting system-trusted CAs
//                 and corporate SSL-bump UnknownAuthorityError).
//                 407 (with Proxy-Authenticate header) = proxy alive (auth required).
//   probeDirect — 3-state probe (directOK | captivePortal | noInternet):
//                 1. Plain HTTP GET (no redirect following) to OS-native portal
//                    check URL (captive.apple.com on macOS/Linux,
//                    www.msftconnecttest.com on Windows).
//                 2. 200 OK with exact expected body => directOK.
//                 3. 3xx redirect, 200 splash HTML, or 511 => anti-spoof TLS
//                    verification to 1.1.1.1:443 (1.5s, verifying Cloudflare's
//                    IP-SAN TLS certificate, NOT just bare TCP open). Real
//                    captive portals either block 443 or present an invalid cert.
//                 4. HTTP/DNS error or timeout => fallback verified TLS to
//                    1.1.1.1:443; if that fails too => noInternet.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/internal/manager"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/network_iface"
)

const (
	probeConnectHost     = "captive.apple.com:443"
	probeConnectHostName = "captive.apple.com"
	probeDirectIP        = "1.1.1.1:443"
	probeDirectTLSName   = "1.1.1.1"
	probeTimeout         = 3 * time.Second
	probeTLSTimeout      = 1500 * time.Millisecond

	// OS-native captive portal URLs — same ones the OS uses internally.
	// Body must match exactly; any redirect or non-matching splash HTML = captive portal.
	portalURLMac  = "http://captive.apple.com/hotspot-detect.html"
	portalURLWin  = "http://www.msftconnecttest.com/connecttest.txt"
	portalBodyMac = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
	portalBodyWin = "Microsoft Connect Test"
)

// DirectProbeState is the 3-state result of probeDirect().
type DirectProbeState string

const (
	directOK      DirectProbeState = "direct_ok"
	captivePortal DirectProbeState = "captive_portal"
	noInternet    DirectProbeState = "no_internet"
)

// DirectProbeResult carries the 3-state probe outcome and optional portal redirect URL.
type DirectProbeResult struct {
	State       DirectProbeState
	RedirectURL string
	Err         error
}

// directProbeConfig allows deterministic unit tests with local HTTP/TLS mocks.
type directProbeConfig struct {
	portalURL       string
	expectedBody    string
	directTLSTarget string
	tlsServerName   string
	tlsRootCAs      *x509.CertPool // nil => system roots
	httpTimeout     time.Duration
	tlsTimeout      time.Duration
	dialContext     func(ctx context.Context, network, addr string) (net.Conn, error)
}

func defaultDirectProbeConfig() directProbeConfig {
	portalURL := portalURLMac
	expectedBody := portalBodyMac
	if runtime.GOOS == "windows" {
		portalURL = portalURLWin
		expectedBody = portalBodyWin
	}
	return directProbeConfig{
		portalURL:       portalURL,
		expectedBody:    expectedBody,
		directTLSTarget: probeDirectIP,
		tlsServerName:   probeDirectTLSName,
		httpTimeout:     probeTimeout,
		tlsTimeout:      probeTLSTimeout,
		dialContext:     dialDirectBypassTun,
	}
}

// isTunActive reports whether Lux currently has an active TUN device/monitor.
func isTunActive() bool {
	return manager.GetIsStarted() && network_iface.GetDefaultInterfaceMonitor() != nil
}

// activePhysicalInterface returns the verified non-TUN physical interface name,
// or "" if none is currently known.
func activePhysicalInterface() string {
	for _, candidate := range []string{
		network_iface.GetDefaultInterfaceName(),
		dialer.DefaultInterface.Load(),
	} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || pac.IsExcludedTunIface(candidate) {
			continue
		}
		return candidate
	}
	return ""
}

// dialDirectBypassTun resolves non-IP hostnames via uncached real LAN DNS
// (never Fake-IP, and never OS hijacked DNS while TUN is active) and dials
// directly via the verified physical NIC.
//
// Fail-closed guard: when TUN is active and no verified non-TUN physical
// interface exists, returns an error rather than falling back to
// WithInterface("") (which would route the probe back through Lux's own TUN).
func dialDirectBypassTun(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	tunActive := isTunActive()

	targetHost := host
	if net.ParseIP(host) == nil {
		resolved := pac.LookupFreshIPv4Strict(ctx, host, tunActive)
		if resolved == "" {
			return nil, fmt.Errorf("resolve %s: no non-fake IPv4 address", host)
		}
		targetHost = resolved
	}

	targetIP := net.ParseIP(targetHost)
	if targetIP != nil && targetIP.IsLoopback() {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(targetHost, port))
	}

	defIface := activePhysicalInterface()
	if tunActive && defIface == "" {
		return nil, fmt.Errorf("no verified non-TUN physical interface for direct probe to %s", addr)
	}

	var opts []dialer.Option
	if defIface != "" {
		opts = append(opts, dialer.WithInterface(defIface))
	} else {
		opts = append(opts, dialer.WithInterface(""))
	}
	return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(targetHost, port), opts...)
}

// dialProxyBypassTun dials a configured proxy server without letting TUN hijack
// public proxies, while still permitting private/VPN-routed proxies (e.g.
// 10.8.0.1:8082 over WireGuard or house LAN) via the kernel routing table.
func dialProxyBypassTun(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	tunActive := isTunActive()

	targetHost := host
	if net.ParseIP(host) == nil {
		resolved := pac.LookupFreshIPv4Strict(ctx, host, tunActive)
		if resolved == "" {
			return nil, fmt.Errorf("resolve proxy %s: no non-fake IPv4 address", host)
		}
		targetHost = resolved
	}

	targetIP := net.ParseIP(targetHost)
	if targetIP != nil && targetIP.IsLoopback() {
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(targetHost, port))
	}

	defIface := activePhysicalInterface()
	if tunActive && targetIP != nil && !targetIP.IsPrivate() && !pac.IsBypassed(targetIP) {
		if defIface == "" {
			return nil, fmt.Errorf("no verified non-TUN physical interface for proxy %s", addr)
		}
		return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(targetHost, port), dialer.WithInterface(defIface))
	}

	// Private / bypassed / WireGuard proxy (e.g. 10.8.0.1:8082): let the kernel
	// pick the right interface (LAN or WireGuard utun) rather than pinning en0.
	return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(targetHost, port), dialer.WithInterface(""))
}

// ProbeResult holds the outcome of probing one proxy.
type ProbeResult struct {
	ProxyID string
	Alive   bool
	Latency time.Duration
	Err     error
}

// probeProxy tests a proxy via HTTP CONNECT.
// Returns Alive=true for:
//   - 200 OK followed by a completed TLS handshake to captive.apple.com
//     (accepts system-trusted certs and institutional SSL-bump UnknownAuthorityError,
//     rejects plaintext HTTP splash pages, resets, and wrong-host certs).
//   - 407 Proxy Authentication Required with a Proxy-Authenticate header.
func probeProxy(host string, port int, username, password string) ProbeResult {
	return probeProxyWithTLS(host, port, username, password, nil)
}

func probeProxyWithTLS(host string, port int, username, password string, rootCAs *x509.CertPool) ProbeResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	c, err := dialProxyBypassTun(ctx, addr)
	if err != nil {
		return ProbeResult{Alive: false, Err: err}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(probeTimeout))

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", probeConnectHost, probeConnectHost)
	if username != "" {
		raw := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req += "Proxy-Authorization: Basic " + raw + "\r\n"
	}
	req += "\r\n"

	if _, err = c.Write([]byte(req)); err != nil {
		return ProbeResult{Alive: false, Err: err}
	}

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return ProbeResult{Alive: false, Err: err}
	}
	resp.Body.Close()
	latency := time.Since(start)

	if resp.StatusCode == http.StatusProxyAuthRequired {
		if strings.TrimSpace(resp.Header.Get("Proxy-Authenticate")) == "" {
			return ProbeResult{
				Alive:   false,
				Latency: latency,
				Err:     fmt.Errorf("proxy returned 407 without Proxy-Authenticate header"),
			}
		}
		return ProbeResult{Alive: true, Latency: latency}
	}

	if resp.StatusCode == http.StatusOK {
		// Verify the CONNECT tunnel actually speaks TLS for captive.apple.com,
		// so a rogue hotel/gateway HTTP responder returning bare 200 OK cannot
		// spoof a healthy corporate proxy.
		tunnelConn := &bufferedConn{Conn: c, r: br}
		tlsCfg := &tls.Config{
			ServerName: probeConnectHostName,
			RootCAs:    rootCAs,
		}
		tlsConn := tls.Client(tunnelConn, tlsCfg)
		tlsErr := tlsConn.HandshakeContext(ctx)
		if tlsErr == nil {
			return ProbeResult{Alive: true, Latency: time.Since(start)}
		}
		// Corporate Squid SSL-bump proxies may present an institutional CA not
		// yet installed in the OS root store; x509.UnknownAuthorityError still
		// proves a real TLS handshake for the requested hostname took place.
		var unknownAuth x509.UnknownAuthorityError
		if errors.As(tlsErr, &unknownAuth) {
			return ProbeResult{Alive: true, Latency: time.Since(start)}
		}
		return ProbeResult{
			Alive:   false,
			Latency: time.Since(start),
			Err:     fmt.Errorf("CONNECT 200 TLS check failed: %w", tlsErr),
		}
	}

	return ProbeResult{
		Alive:   false,
		Latency: latency,
		Err:     fmt.Errorf("proxy returned %d", resp.StatusCode),
	}
}

// bufferedConn wraps a net.Conn with any bytes already buffered by bufio.Reader.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// ProxyCandidate is the input type for probeProxiesParallel.
type ProxyCandidate struct {
	ID       string
	Host     string
	Port     int
	Username string
	Password string
}

// probeProxiesParallel probes all candidates in parallel.
// Results are returned in the same order as input (priority order preserved).
func probeProxiesParallel(candidates []ProxyCandidate) []ProbeResult {
	results := make([]ProbeResult, len(candidates))
	var wg sync.WaitGroup
	for i, c := range candidates {
		wg.Add(1)
		go func(idx int, cand ProxyCandidate) {
			defer wg.Done()
			r := probeProxy(cand.Host, cand.Port, cand.Username, cand.Password)
			r.ProxyID = cand.ID
			results[idx] = r
		}(i, c)
	}
	wg.Wait()
	return results
}

// probeDirect probes direct internet / captive-portal status using OS-native
// portal URLs via Lux's TUN-exempt outbound dialer and real LAN DNS.
func probeDirect() DirectProbeResult {
	return probeDirectWithConfig(defaultDirectProbeConfig())
}

func probeDirectWithConfig(cfg directProbeConfig) DirectProbeResult {
	if cfg.httpTimeout <= 0 {
		cfg.httpTimeout = probeTimeout
	}
	if cfg.tlsTimeout <= 0 {
		cfg.tlsTimeout = probeTLSTimeout
	}
	if cfg.dialContext == nil {
		cfg.dialContext = dialDirectBypassTun
	}
	if cfg.tlsServerName == "" {
		cfg.tlsServerName = probeDirectTLSName
	}

	// probeVerifiedTLS443 dials 1.1.1.1:443 and performs a full TLS handshake
	// verifying Cloudflare's IP-SAN certificate. Bare TCP connect is NOT enough:
	// many captive portals transparently accept TCP/443 (then stall or present
	// an untrusted portal certificate).
	probeVerifiedTLS443 := func() bool {
		if cfg.directTLSTarget == "" {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), cfg.tlsTimeout)
		defer cancel()
		rawConn, err := cfg.dialContext(ctx, "tcp4", cfg.directTLSTarget)
		if err != nil {
			return false
		}
		defer rawConn.Close()
		_ = rawConn.SetDeadline(time.Now().Add(cfg.tlsTimeout))

		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName: cfg.tlsServerName,
			RootCAs:    cfg.tlsRootCAs,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return false
		}
		return true
	}

	tr := &http.Transport{
		Proxy:             nil, // NEVER honor HTTP_PROXY env var (e.g. 127.0.0.1:1090)
		DialContext:       cfg.dialContext,
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Timeout:   cfg.httpTimeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // inspect 3xx directly
		},
	}

	resp, err := client.Get(cfg.portalURL)
	if err != nil {
		// HTTP/DNS failure or timeout: fall back to verified TLS 1.1.1.1:443.
		if probeVerifiedTLS443() {
			return DirectProbeResult{State: directOK}
		}
		return DirectProbeResult{State: noInternet, Err: err}
	}
	defer resp.Body.Close()

	// Case 1: 200 OK — verify exact expected body.
	if resp.StatusCode == http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr == nil && strings.TrimSpace(string(body)) == cfg.expectedBody {
			return DirectProbeResult{State: directOK}
		}
		// 200 OK with non-matching body (portal splash HTML): anti-spoof TLS check.
		if probeVerifiedTLS443() {
			log.Warnln("[net-probe] portal body mismatch on %s but verified TLS to %s succeeded — treating as directOK (anti-spoof)",
				cfg.portalURL, cfg.directTLSTarget)
			return DirectProbeResult{State: directOK}
		}
		return DirectProbeResult{State: captivePortal}
	}

	// Case 2: 3xx redirect or RFC 6585 511 Network Authentication Required.
	if (resp.StatusCode >= 300 && resp.StatusCode < 400) ||
		resp.StatusCode == http.StatusNetworkAuthenticationRequired {
		redirectURL := strings.TrimSpace(resp.Header.Get("Location"))
		// Anti-spoofing guard: real captive portals cannot present a valid
		// certificate for 1.1.1.1:443. If verified TLS succeeds while port 80
		// redirects, refuse captive pause.
		if probeVerifiedTLS443() {
			log.Warnln("[net-probe] HTTP %d (%s) on %s but verified TLS to %s succeeded — treating as directOK (anti-spoof)",
				resp.StatusCode, redirectURL, cfg.portalURL, cfg.directTLSTarget)
			return DirectProbeResult{State: directOK}
		}
		return DirectProbeResult{
			State:       captivePortal,
			RedirectURL: redirectURL,
		}
	}

	// Case 3: Other unexpected HTTP status (e.g. 500/503) — fall back to verified TLS 443.
	if probeVerifiedTLS443() {
		return DirectProbeResult{State: directOK}
	}
	return DirectProbeResult{
		State: noInternet,
		Err:   fmt.Errorf("portal probe returned HTTP %d", resp.StatusCode),
	}
}
