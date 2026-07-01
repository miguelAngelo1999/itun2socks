package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/atomic"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/conn"
	"github.com/igoogolx/itun2socks/internal/tunnel/statistic"
	"github.com/igoogolx/itun2socks/pkg/log"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
)

// patchedConn wraps a net.Conn and replaces its Read source with a patched reader.
// Used to fix TLS 1.0 record headers before Go's TLS stack sees them.
type patchedConn struct {
	net.Conn
	reader io.Reader
}

func (c *patchedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// MitmInterceptor performs selective TLS interception on CONNECT tunnels.
type MitmInterceptor struct {
	ca             *CA
	inspectionList *InspectionList
	enabled        *atomic.Bool
}

// NewMitmInterceptor constructs a MitmInterceptor (disabled by default).
func NewMitmInterceptor(ca *CA, list *InspectionList) *MitmInterceptor {
	return &MitmInterceptor{
		ca:             ca,
		inspectionList: list,
		enabled:        atomic.NewBool(false),
	}
}

// SetEnabled toggles global SSL inspection on or off.
func (m *MitmInterceptor) SetEnabled(v bool) { m.enabled.Store(v) }

// IsEnabled reports whether SSL inspection is currently enabled.
func (m *MitmInterceptor) IsEnabled() bool { return m.enabled.Load() }

// InspectionList returns the underlying InspectionList (satisfies InterceptorWithList).
func (m *MitmInterceptor) InspectionList() *InspectionList { return m.inspectionList }

// ShouldIntercept returns true when SSL inspection is enabled and the domain is
// explicitly in the inspection list. Inspection list takes precedence over bypass —
// if a user adds googleapis.com to inspect, it will be intercepted regardless of bypass.
func (m *MitmInterceptor) ShouldIntercept(domain string) bool {
	if !m.enabled.Load() {
		return false
	}
	// Inspection list overrides bypass list — explicit user config wins
	return m.inspectionList.Contains(domain)
}

// Intercept performs full MITM TLS interception for an HTTP CONNECT tunnel.
// clientConn is the raw TCP connection from the client; host is the CONNECT target.
// The caller must NOT have replied 200 to the client yet.
func (m *MitmInterceptor) Intercept(
	clientConn net.Conn,
	host string,
	statsManager *statistic.Manager,
	rule rule_engine.Rule,
) error {
	sniHost, port := splitHostPort(host)
	dialAddr := net.JoinHostPort(sniHost, port)

	// Dial upstream TCP.
	upstreamTCP, err := net.DialTimeout("tcp", dialAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("mitm: dial upstream %s: %w", dialAddr, err)
	}

	// TLS handshake with upstream (normal cert verification, force HTTP/1.1).
	upstreamTLS := tls.Client(upstreamTCP, &tls.Config{
		ServerName:         sniHost,
		InsecureSkipVerify: false,
		NextProtos:         []string{"http/1.1"},
	})
	if err := upstreamTLS.Handshake(); err != nil {
		upstreamTCP.Close()
		return fmt.Errorf("mitm: upstream TLS handshake with %s: %w", sniHost, err)
	}

	// Obtain leaf cert for sniHost.
	if _, err = m.ca.GetOrCreateLeafCert(sniHost); err != nil {
		upstreamTCP.Close()
		return fmt.Errorf("mitm: get leaf cert for %s: %w", sniHost, err)
	}

	// Reply 200 to client.
	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		upstreamTCP.Close()
		return fmt.Errorf("mitm: write 200 to client: %w", err)
	}

	// TLS handshake with client.
	tlsClientConn := tls.Server(clientConn, m.ca.TLSConfig())
	if err := tlsClientConn.Handshake(); err != nil {
		tlsClientConn.Close()
		upstreamTCP.Close()
		return fmt.Errorf("mitm: client TLS handshake for %s: %w", sniHost, err)
	}

	defer tlsClientConn.Close()
	defer upstreamTCP.Close()

	// HTTP/1.1 request-response loop.
	clientReader := bufio.NewReader(tlsClientConn)
	upstreamReader := bufio.NewReader(upstreamTLS)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			return nil // EOF or client closed
		}

		fullURL := "https://" + sniHost + req.URL.RequestURI()
		req.URL.Scheme = "https"
		req.URL.Host = sniHost
		req.RequestURI = ""
		removeHopByHopHeaders(req.Header)

		if err := req.Write(upstreamTLS); err != nil {
			return fmt.Errorf("mitm: write request to upstream: %w", err)
		}

		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			return fmt.Errorf("mitm: read response from upstream: %w", err)
		}

		tracker := statistic.NewTCPTracker(tlsClientConn, statsManager, nil, rule)
		tracker.SetInspectedMeta(true, fullURL)

		if err := resp.Write(tracker); err != nil {
			resp.Body.Close()
			return fmt.Errorf("mitm: write response to client: %w", err)
		}
		resp.Body.Close()

		if resp.Close || req.Close {
			return nil
		}
	}
}

// InterceptRaw performs TLS MITM interception on a raw TLS connection (TUN mode).
// Unlike Intercept(), this does NOT send HTTP/1.1 200 — the client is already
// sending raw TLS, not wrapped in HTTP CONNECT.
func (m *MitmInterceptor) InterceptRaw(
	ctx context.Context,
	clientConn net.Conn,
	host string,
	statsManager *statistic.Manager,
	rule rule_engine.Rule,
	defaultInterface string,
) error {
	sniHost, port := splitHostPort(host)

	// Dial upstream through the proxy chain
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Host:    sniHost,
		DstPort: func() C.Port {
			p, _ := strconv.ParseUint(port, 10, 16)
			return C.Port(p)
		}(),
	}

	upstreamTCP, err := conn.NewTcpConn(ctx, metadata, rule, defaultInterface)
	if err != nil {
		return fmt.Errorf("mitm: dial upstream %s via proxy: %w", net.JoinHostPort(sniHost, port), err)
	}

	// TLS handshake with upstream
	// InsecureSkipVerify=true because the upstream cert comes from the corporate proxy
	// SSL bump (Squid) which re-signs with its own CA that may lack CRL DPs.
	// We don't need to verify here — lux is acting as a local MITM and we trust
	// the corporate proxy connection (we're on the internal network).
	upstreamTLS := tls.Client(upstreamTCP, &tls.Config{
		ServerName:         sniHost,
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"http/1.1"},
	})
	if err := upstreamTLS.Handshake(); err != nil {
		upstreamTCP.Close()
		return fmt.Errorf("mitm: upstream TLS handshake with %s: %w", sniHost, err)
	}

	if _, err = m.ca.GetOrCreateLeafCert(sniHost); err != nil {
		upstreamTCP.Close()
		return fmt.Errorf("mitm: get leaf cert for %s: %w", sniHost, err)
	}

	// Peek and patch TLS 1.0 record headers
	br := bufio.NewReader(clientConn)
	header, err := br.Peek(3)
	if err == nil && len(header) == 3 && header[0] == 0x16 {
		if header[1] == 0x03 && header[2] == 0x01 {
			peeked := make([]byte, 3)
			_, _ = br.Read(peeked)
			peeked[2] = 0x03
			clientConn = &patchedConn{
				Conn:   clientConn,
				reader: io.MultiReader(bytes.NewReader(peeked), br),
			}
		}
	}

	// TLS handshake with client (raw — no HTTP framing)
	tlsClientConn := tls.Server(clientConn, m.ca.TLSConfig())
	if err := tlsClientConn.Handshake(); err != nil {
		tlsClientConn.Close()
		upstreamTCP.Close()
		return fmt.Errorf("mitm: client TLS handshake for %s: %w", sniHost, err)
	}

	defer tlsClientConn.Close()
	defer upstreamTCP.Close()

	// If HTTP/2 was negotiated, fall back to transparent relay.
	// We can't parse HTTP/2 frames — just relay bytes bidirectionally.
	if tlsClientConn.ConnectionState().NegotiatedProtocol == "h2" {
		log.Infoln("[MITM] h2 relay: %s", sniHost)
		return relay(tlsClientConn, upstreamTLS)
	}

	clientReader := bufio.NewReader(tlsClientConn)
	upstreamReader := bufio.NewReader(upstreamTLS)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			return nil
		}

		fullURL := "https://" + sniHost + req.URL.RequestURI()
		log.Infoln("%s", "[MITM], "+req.Method+" "+fullURL)
		req.URL.Scheme = "https"
		req.URL.Host = sniHost
		req.RequestURI = ""
		removeHopByHopHeaders(req.Header)

		if err := req.Write(upstreamTLS); err != nil {
			return fmt.Errorf("mitm: write request to upstream: %w", err)
		}

		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			return fmt.Errorf("mitm: read response from upstream: %w", err)
		}

		tracker := statistic.NewTCPTracker(tlsClientConn, statsManager, nil, rule)
		tracker.SetInspectedMeta(true, fullURL)

		if err := resp.Write(tracker); err != nil {
			resp.Body.Close()
			return fmt.Errorf("mitm: write response to client: %w", err)
		}
		resp.Body.Close()

		if resp.Close || req.Close {
			return nil
		}
	}
}

// relay copies bytes bidirectionally between two connections (for HTTP/2 and other protocols).
func relay(a, b net.Conn) error {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	return nil
}

func splitHostPort(hostport string) (host, port string) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.TrimSpace(hostport), "443"
	}
	if p == "" {
		p = "443"
	}
	return h, p
}

func removeHopByHopHeaders(h http.Header) {
	for _, conn := range h["Connection"] {
		for _, f := range strings.Split(conn, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
	for _, header := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Proxy-Connection", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(header)
	}
}
