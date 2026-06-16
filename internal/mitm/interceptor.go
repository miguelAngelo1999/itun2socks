package mitm

import (
"bufio"
"crypto/tls"
"fmt"
"io"
"net"
"net/http"
"strings"
"time"

"go.uber.org/atomic"

"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
"github.com/igoogolx/itun2socks/internal/tunnel/statistic"
)

// MitmInterceptor performs selective TLS interception on CONNECT tunnels.
// It is safe for concurrent use.
type MitmInterceptor struct {
ca             *CA
inspectionList *InspectionList
enabled        *atomic.Bool
}

// NewMitmInterceptor constructs a MitmInterceptor. It is disabled by default;
// call SetEnabled(true) to activate interception.
func NewMitmInterceptor(ca *CA, list *InspectionList) *MitmInterceptor {
return &MitmInterceptor{
ca:             ca,
inspectionList: list,
enabled:        atomic.NewBool(false),
}
}

// SetEnabled toggles global SSL inspection on or off.
func (m *MitmInterceptor) SetEnabled(v bool) {
m.enabled.Store(v)
}

// IsEnabled reports whether SSL inspection is currently enabled.
func (m *MitmInterceptor) IsEnabled() bool {
return m.enabled.Load()
}

// InspectionList returns the underlying InspectionList (satisfies InterceptorWithList).
func (m *MitmInterceptor) InspectionList() *InspectionList {
return m.inspectionList
}

// ShouldIntercept returns true when SSL inspection is globally enabled,
// the domain is not in the hardcoded bypass list, and the domain appears
// in the (enabled) inspection list.
func (m *MitmInterceptor) ShouldIntercept(domain string) bool {
if !m.enabled.Load() {
return false
}
if IsBypassed(domain) {
return false
}
return m.inspectionList.Contains(domain)
}

// Intercept performs full MITM TLS interception for an HTTP CONNECT tunnel.
//
// clientConn is the raw TCP connection from the client that has already sent
// an HTTP CONNECT request. host is the CONNECT target ("domain:port" or
// "domain"). The caller must NOT have replied 200 to the client yet -
// Intercept handles the 200 response itself.
//
// The function:
//  1. Dials the upstream TCP connection.
//  2. Performs a TLS handshake with the upstream server (normal cert verification).
//  3. Generates / fetches the leaf certificate for the SNI hostname.
//  4. Sends "HTTP/1.1 200 Connection Established" to the client.
//  5. Wraps clientConn in a TLS server using the leaf cert.
//  6. Reads HTTP/1.1 request(s) from the TLS client connection.
//  7. Forwards each request to the upstream TLS connection.
//  8. Writes each response back to the client.
//  9. Records the connection in the statistic manager with inspected metadata.
func (m *MitmInterceptor) Intercept(
clientConn net.Conn,
host string,
statsManager *statistic.Manager,
rule rule_engine.Rule,
) error {
// Step 1: parse the host into sniHost + dialAddr.
sniHost, port := splitHostPort(host)
dialAddr := net.JoinHostPort(sniHost, port)

// Step 2: dial upstream TCP.
upstreamTCP, err := net.DialTimeout("tcp", dialAddr, 10*time.Second)
if err != nil {
return fmt.Errorf("mitm: dial upstream %s: %w", dialAddr, err)
}

// Step 3: TLS handshake with upstream (verify normally).
upstreamTLS := tls.Client(upstreamTCP, &tls.Config{
ServerName:         sniHost,
InsecureSkipVerify: false,
// Force HTTP/1.1 so we can speak HTTP/1.1 with the upstream.
NextProtos: []string{"http/1.1"},
})
if err := upstreamTLS.Handshake(); err != nil {
upstreamTCP.Close()
return fmt.Errorf("mitm: upstream TLS handshake with %s: %w", sniHost, err)
}

// Step 4: obtain leaf certificate for sniHost.
_, err = m.ca.GetOrCreateLeafCert(sniHost)
if err != nil {
upstreamTCP.Close()
return fmt.Errorf("mitm: get leaf cert for %s: %w", sniHost, err)
}

// Step 5: reply 200 Connection Established to client.
if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
upstreamTCP.Close()
return fmt.Errorf("mitm: write 200 to client: %w", err)
}

// Step 6: TLS handshake with client (using leaf cert).
tlsClientConn := tls.Server(clientConn, m.ca.TLSConfig())
if err := tlsClientConn.Handshake(); err != nil {
tlsClientConn.Close()
upstreamTCP.Close()
return fmt.Errorf("mitm: client TLS handshake for %s: %w", sniHost, err)
}

defer tlsClientConn.Close()
defer upstreamTCP.Close()

// Steps 7-9: HTTP/1.1 request-response loop.
clientReader := bufio.NewReader(tlsClientConn)
upstreamReader := bufio.NewReader(upstreamTLS)

for {
req, err := http.ReadRequest(clientReader)
if err != nil {
// EOF or client closed - normal end of session.
return nil
}

// Build the full URL for tracking and rule evaluation.
fullURL := "https://" + sniHost + req.URL.RequestURI()

// Fix up the request so it can be forwarded to the upstream.
req.URL.Scheme = "https"
req.URL.Host = sniHost
req.RequestURI = "" // must be cleared for outbound requests

// Remove hop-by-hop headers.
removeHopByHopHeaders(req.Header)

// Forward request to upstream over the existing TLS connection.
if err := req.Write(upstreamTLS); err != nil {
return fmt.Errorf("mitm: write request to upstream: %w", err)
}

// Read response from upstream.
resp, err := http.ReadResponse(upstreamReader, req)
if err != nil {
return fmt.Errorf("mitm: read response from upstream: %w", err)
}

// Use a tracker so the stats manager can record this connection with
// full URL and inspected flag.
tracker := statistic.NewTCPTracker(tlsClientConn, statsManager, nil, rule)
tracker.SetInspectedMeta(true, fullURL)

// Write response back to the TLS client through the tracker so
// upload bytes are counted.
if err := resp.Write(tracker); err != nil {
resp.Body.Close()
return fmt.Errorf("mitm: write response to client: %w", err)
}
resp.Body.Close()

// Honour connection-close semantics - break after first exchange
// if either side requested close (v1 behaviour; no persistent connections).
if resp.Close || req.Close {
return nil
}
}
}

// splitHostPort splits "host:port" into its components.
// If no port is present it returns "443" as the default.
func splitHostPort(hostport string) (host, port string) {
h, p, err := net.SplitHostPort(hostport)
if err != nil {
// No port separator - treat the whole string as a host.
return strings.TrimSpace(hostport), "443"
}
if p == "" {
p = "443"
}
return h, p
}

// removeHopByHopHeaders strips HTTP hop-by-hop headers that must not be
// forwarded to the next hop.
func removeHopByHopHeaders(h http.Header) {
hopByHop := []string{
"Connection",
"Keep-Alive",
"Proxy-Authenticate",
"Proxy-Authorization",
"Proxy-Connection",
"Te",
"Trailers",
"Transfer-Encoding",
"Upgrade",
}
// Also honour any headers listed in the Connection header value itself.
for _, conn := range h["Connection"] {
for _, f := range strings.Split(conn, ",") {
h.Del(strings.TrimSpace(f))
}
}
for _, header := range hopByHop {
h.Del(header)
}
}
