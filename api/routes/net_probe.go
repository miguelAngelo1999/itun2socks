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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/manager"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/network_iface"
	"os"
	"path/filepath"
)

const (
	probeConnectHost     = "captive.apple.com:443"
	probeConnectHostName = "captive.apple.com"
	healthCheckHost      = "www.gstatic.com:443"
	healthCheckHostName  = "www.gstatic.com"
	healthCheckPath      = "/generate_204"
	probeDirectIP        = "1.1.1.1:443"
	probeDirectTLSName   = "1.1.1.1"
	probeTimeout         = 3 * time.Second
	healthProbeTimeout   = 5 * time.Second
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
	ProxyID      string
	Alive        bool
	AuthRequired bool // true when proxy returned 407 / SOCKS5 auth rejection
	Latency      time.Duration
	Err          error
}

// probeProxy tests an HTTP proxy via HTTP CONNECT (reachability probe).
// Returns Alive=true for:
//   - 200 OK followed by a completed TLS handshake to captive.apple.com
//     (accepts system-trusted certs and institutional SSL-bump UnknownAuthorityError,
//     rejects plaintext HTTP splash pages, resets, and wrong-host certs).
//   - 407 Proxy Authentication Required with a Proxy-Authenticate header
//     (sets AuthRequired=true so Stay-Connected skips bad-credential backups
//     while Home/Office still knows the corporate proxy is reachable).
func probeProxy(host string, port int, username, password string) ProbeResult {
	return probeHTTPProxy(host, port, username, password, nil, false)
}

func probeProxyWithTLS(host string, port int, username, password string, rootCAs *x509.CertPool) ProbeResult {
	return probeHTTPProxy(host, port, username, password, rootCAs, false)
}

// probeHTTPProxy probes an HTTP proxy. When requireHTTP204 is true (Stay-Connected
// health check), it completes an end-to-end HTTPS GET www.gstatic.com/generate_204
// through the proxy and treats 407 as Alive=false, AuthRequired=true.
func probeHTTPProxy(host string, port int, username, password string, rootCAs *x509.CertPool, requireHTTP204 bool) ProbeResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()
	timeout := probeTimeout
	targetAddr := probeConnectHost
	targetHost := probeConnectHostName
	if requireHTTP204 {
		timeout = healthProbeTimeout
		targetAddr = healthCheckHost
		targetHost = healthCheckHostName
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c, err := dialProxyBypassTun(ctx, addr)
	if err != nil {
		return ProbeResult{Alive: false, Err: err}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
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
		if requireHTTP204 {
			return ProbeResult{
				Alive:        false,
				AuthRequired: true,
				Latency:      latency,
				Err:          fmt.Errorf("proxy auth required (407)"),
			}
		}
		return ProbeResult{Alive: true, AuthRequired: true, Latency: latency}
	}

	if resp.StatusCode == http.StatusOK {
		tunnelConn := &bufferedConn{Conn: c, r: br}
		return verifyTunnelTLSAndOptional204(ctx, tunnelConn, targetHost, rootCAs, requireHTTP204, start)
	}

	return ProbeResult{
		Alive:   false,
		Latency: latency,
		Err:     fmt.Errorf("proxy returned %d", resp.StatusCode),
	}
}

// probeSOCKS5Proxy probes a SOCKS5 proxy (RFC 1928 + optional RFC 1929 user/pass),
// establishes a CONNECT tunnel to targetAddr, and verifies TLS (plus optional HTTP 204).
func probeSOCKS5Proxy(host string, port int, username, password string, rootCAs *x509.CertPool, requireHTTP204 bool) ProbeResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()
	timeout := probeTimeout
	targetHost := probeConnectHostName
	targetPort := uint16(443)
	if requireHTTP204 {
		timeout = healthProbeTimeout
		targetHost = healthCheckHostName
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c, err := dialProxyBypassTun(ctx, addr)
	if err != nil {
		return ProbeResult{Alive: false, Err: err}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	// 1. Greeting: no-auth (0x00), plus user/pass (0x02) if credentials provided.
	var greet []byte
	if username != "" || password != "" {
		greet = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greet = []byte{0x05, 0x01, 0x00}
	}
	if _, err := c.Write(greet); err != nil {
		return ProbeResult{Alive: false, Err: err}
	}
	var methodResp [2]byte
	if _, err := io.ReadFull(c, methodResp[:]); err != nil {
		return ProbeResult{Alive: false, Err: err}
	}
	if methodResp[0] != 0x05 {
		return ProbeResult{Alive: false, Err: fmt.Errorf("not a SOCKS5 server")}
	}
	switch methodResp[1] {
	case 0x00:
		// No auth needed
	case 0x02:
		if len(username) > 255 || len(password) > 255 {
			return ProbeResult{Alive: false, AuthRequired: true, Err: fmt.Errorf("credentials too long")}
		}
		authReq := make([]byte, 0, 3+len(username)+len(password))
		authReq = append(authReq, 0x01, byte(len(username)))
		authReq = append(authReq, username...)
		authReq = append(authReq, byte(len(password)))
		authReq = append(authReq, password...)
		if _, err := c.Write(authReq); err != nil {
			return ProbeResult{Alive: false, Err: err}
		}
		var authResp [2]byte
		if _, err := io.ReadFull(c, authResp[:]); err != nil {
			return ProbeResult{Alive: false, Err: err}
		}
		if authResp[1] != 0x00 {
			return ProbeResult{
				Alive:        !requireHTTP204,
				AuthRequired: true,
				Latency:      time.Since(start),
				Err:          fmt.Errorf("SOCKS5 authentication failed"),
			}
		}
	case 0xFF:
		return ProbeResult{
			Alive:        !requireHTTP204,
			AuthRequired: true,
			Latency:      time.Since(start),
			Err:          fmt.Errorf("SOCKS5 requires authentication"),
		}
	default:
		return ProbeResult{Alive: false, Err: fmt.Errorf("unsupported SOCKS5 auth method %d", methodResp[1])}
	}

	// 2. CONNECT request (ATYP=0x03 domain name)
	req := make([]byte, 0, 7+len(targetHost))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(targetHost)))
	req = append(req, targetHost...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], targetPort)
	req = append(req, portBuf[:]...)
	if _, err := c.Write(req); err != nil {
		return ProbeResult{Alive: false, Err: err}
	}

	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return ProbeResult{Alive: false, Err: err}
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		return ProbeResult{Alive: false, Latency: time.Since(start), Err: fmt.Errorf("SOCKS5 CONNECT failed: code %d", hdr[1])}
	}
	// Drain bound address + port
	var skip int
	switch hdr[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return ProbeResult{Alive: false, Err: err}
		}
		skip = int(l[0]) + 2
	default:
		return ProbeResult{Alive: false, Err: fmt.Errorf("invalid SOCKS5 ATYP %d", hdr[3])}
	}
	if _, err := io.CopyN(io.Discard, c, int64(skip)); err != nil {
		return ProbeResult{Alive: false, Err: err}
	}

	return verifyTunnelTLSAndOptional204(ctx, c, targetHost, rootCAs, requireHTTP204, start)
}

// buildVerifyRootPool returns OS system roots plus any Lux-installed corporate
// CA certificates (in-memory extraRootsPEM and proxy_ca_bundle.pem on disk).
func buildVerifyRootPool() *x509.CertPool {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	extraRootsMu.RLock()
	if len(extraRootsPEM) > 0 {
		roots.AppendCertsFromPEM(extraRootsPEM)
	}
	extraRootsMu.RUnlock()
	if bundlePath := filepath.Join(constants.Path.HomeDir(), "proxy_ca_bundle.pem"); bundlePath != "" {
		if data, err := os.ReadFile(bundlePath); err == nil && len(data) > 0 {
			roots.AppendCertsFromPEM(data)
		}
	}
	return roots
}

// verifyTunnelTLSAndOptional204 validates TLS through an established proxy tunnel
// and, when requireHTTP204 is true, performs GET /generate_204 to prove real
// upstream internet connectivity.
func verifyTunnelTLSAndOptional204(
	ctx context.Context,
	tunnelConn net.Conn,
	targetHost string,
	rootCAs *x509.CertPool,
	requireHTTP204 bool,
	start time.Time,
) ProbeResult {
	roots := rootCAs
	if roots == nil {
		roots = buildVerifyRootPool()
	}
	tlsCfg := &tls.Config{
		ServerName: targetHost,
		RootCAs:    roots,
	}
	tlsConn := tls.Client(tunnelConn, tlsCfg)
	tlsErr := tlsConn.HandshakeContext(ctx)
	if tlsErr != nil {
		// Corporate Squid SSL-bump proxies may present an institutional CA not
		// yet installed in the OS root store; x509.UnknownAuthorityError still
		// proves a real TLS handshake for the requested hostname took place.
		var unknownAuth x509.UnknownAuthorityError
		if !errors.As(tlsErr, &unknownAuth) {
			return ProbeResult{
				Alive:   false,
				Latency: time.Since(start),
				Err:     fmt.Errorf("tunnel TLS check failed: %w", tlsErr),
			}
		}
		// If we need HTTP 204 through an untrusted bump cert, the handshake above
		// already failed; treat as unreachable unless we retry with SkipVerify
		// only after proving UnknownAuthorityError.
		if requireHTTP204 {
			return ProbeResult{
				Alive:   false,
				Latency: time.Since(start),
				Err:     fmt.Errorf("tunnel TLS untrusted CA on health check: %w", tlsErr),
			}
		}
		return ProbeResult{Alive: true, Latency: time.Since(start)}
	}

	if !requireHTTP204 {
		return ProbeResult{Alive: true, Latency: time.Since(start)}
	}

	// End-to-end HTTP GET /generate_204 through the verified TLS tunnel.
	httpReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Lux-Health/1.0\r\nConnection: close\r\n\r\n",
		healthCheckPath, targetHost)
	if _, err := tlsConn.Write([]byte(httpReq)); err != nil {
		return ProbeResult{Alive: false, Latency: time.Since(start), Err: fmt.Errorf("health GET write: %w", err)}
	}
	hResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		return ProbeResult{Alive: false, Latency: time.Since(start), Err: fmt.Errorf("health GET read: %w", err)}
	}
	hResp.Body.Close()
	if hResp.StatusCode == http.StatusNoContent || hResp.StatusCode == http.StatusOK {
		return ProbeResult{Alive: true, Latency: time.Since(start)}
	}
	return ProbeResult{
		Alive:   false,
		Latency: time.Since(start),
		Err:     fmt.Errorf("health GET returned HTTP %d", hResp.StatusCode),
	}
}

// probePACOnlyProxy evaluates a PAC-only proxy (empty server + pacUrl) to
// determine reachability or end-to-end health.
//
// Crucially, if the PAC script itself cannot be fetched/compiled (e.g. you left
// the office network and http://wpad/wpad.dat is unreachable), this returns
// Alive=false — giving Auto Home/Office an exact Office-vs-Home signal!
func probePACOnlyProxy(cand ProxyCandidate, requireHTTP204 bool) ProbeResult {
	start := time.Now()
	probeHost := probeConnectHostName
	probeURL := "https://" + probeConnectHostName + "/"
	if requireHTTP204 {
		probeHost = healthCheckHostName
		probeURL = "https://" + healthCheckHostName + healthCheckPath
	}

	// Always verify fresh PAC reachability if not compiled or on network change:
	// first check registry; if missing/uncompiled, try RetryCompile and direct Fetch.
	directive, hasPAC, timedOut := pac.DefaultRegistry.EvalDirective(cand.ID, probeURL, probeHost)
	if (!hasPAC || timedOut) && cand.PacURL != "" {
		if pac.DefaultRegistry.RetryCompile(cand.ID) {
			directive, hasPAC, timedOut = pac.DefaultRegistry.EvalDirective(cand.ID, probeURL, probeHost)
		}
		if (!hasPAC || timedOut) {
			// Direct on-demand fetch + compile (bypasses RetryCompile 5s cooldown
			// and works even if DefaultRegistry hasn't registered this ID yet).
			js, err := pac.Fetch(cand.PacURL)
			if err != nil {
				return ProbeResult{
					ProxyID: cand.ID,
					Alive:   false,
					Latency: time.Since(start),
					Err:     fmt.Errorf("PAC unreachable (%s): %w", cand.PacURL, err),
				}
			}
			compiled, err := pac.Compile(js)
			if err != nil {
				return ProbeResult{
					ProxyID: cand.ID,
					Alive:   false,
					Latency: time.Since(start),
					Err:     fmt.Errorf("PAC compile failed: %w", err),
				}
			}
			directive, timedOut = compiled.EvalRaw(probeURL, probeHost)
			hasPAC = true
		}
	}
	if !hasPAC || timedOut {
		return ProbeResult{
			ProxyID: cand.ID,
			Alive:   false,
			Latency: time.Since(start),
			Err:     fmt.Errorf("PAC script unavailable for proxy %s", cand.ID),
		}
	}

	directives := pac.ParseDirectives(directive)
	if len(directives) == 0 {
		return ProbeResult{ProxyID: cand.ID, Alive: false, Latency: time.Since(start), Err: fmt.Errorf("PAC returned no directives")}
	}

	var lastErr error
	for _, d := range directives {
		if d.IsDirect() {
			// PAC server is reachable AND explicitly directs this host DIRECT:
			// verify internet actually works directly.
			dr := probeDirect()
			if dr.State == directOK {
				return ProbeResult{ProxyID: cand.ID, Alive: true, Latency: time.Since(start)}
			}
			lastErr = fmt.Errorf("PAC directive DIRECT but direct probe=%s", dr.State)
			continue
		}
		portNum, err := strconv.Atoi(d.Port)
		if err != nil || d.Host == "" || portNum <= 0 {
			continue
		}
		var res ProbeResult
		if d.Scheme == "socks5" {
			res = probeSOCKS5Proxy(d.Host, portNum, cand.Username, cand.Password, nil, requireHTTP204)
		} else {
			res = probeHTTPProxy(d.Host, portNum, cand.Username, cand.Password, nil, requireHTTP204)
		}
		res.ProxyID = cand.ID
		if res.Alive || res.AuthRequired {
			return res
		}
		lastErr = res.Err
	}

	return ProbeResult{ProxyID: cand.ID, Alive: false, Latency: time.Since(start), Err: lastErr}
}

// probeCandidate probes a single ProxyCandidate (HTTP, SOCKS5, or PAC-only).
func probeCandidate(cand ProxyCandidate, requireHTTP204 bool) ProbeResult {
	var r ProbeResult
	if cand.Host == "" && cand.PacURL != "" {
		r = probePACOnlyProxy(cand, requireHTTP204)
	} else if strings.EqualFold(cand.Type, "socks5") || strings.EqualFold(cand.Type, "socks") {
		r = probeSOCKS5Proxy(cand.Host, cand.Port, cand.Username, cand.Password, nil, requireHTTP204)
	} else {
		r = probeHTTPProxy(cand.Host, cand.Port, cand.Username, cand.Password, nil, requireHTTP204)
	}
	r.ProxyID = cand.ID
	return r
}

// probeProxyHealth performs a real end-to-end internet check (GET /generate_204
// through the proxy) used by Stay-Connected failover.
func probeProxyHealth(cand ProxyCandidate) ProbeResult {
	return probeCandidate(cand, true)
}

// bufferedConn wraps a net.Conn with any bytes already buffered by bufio.Reader.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// ProxyCandidate is the input type for probeProxiesParallel and probeProxyHealth.
type ProxyCandidate struct {
	ID       string
	Type     string // "http", "socks5", etc.
	Host     string // empty for PAC-only
	Port     int    // 0 for PAC-only
	PacURL   string // non-empty for PAC-only or PAC-attached
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
			results[idx] = probeCandidate(cand, false)
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
