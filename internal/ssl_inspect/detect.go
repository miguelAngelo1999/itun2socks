package ssl_inspect

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	probeHost = "captive.apple.com"
	probePort = "443"
)

// BumpStatus is the result of an SSL-bump detection probe.
type BumpStatus struct {
	Detected    bool   `json:"detected"`
	InterceptCA []byte `json:"interceptCa,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Detect probes captive.apple.com and checks whether the certificate chain
// contains an unexpected root CA (SSL bumping / interception).
//
// Detection strategy:
//  1. Try via the system HTTP proxy (HTTP_PROXY / HTTPS_PROXY env vars, or
//     the proxy set in WinInet on Windows) — this is what the corporate proxy
//     would intercept.
//  2. Fall back to a direct TCP connection if no system proxy is configured.
func Detect() BumpStatus {
	return DetectVia(nil)
}

// DetectVia probes for SSL bumping through an explicit proxyURL.
// If proxyURL is nil, falls back to the system proxy then direct.
func DetectVia(proxyURL *url.URL) BumpStatus {
	if proxyURL != nil {
		return detectViaProxy(proxyURL)
	}
	// Try probing through the system proxy first.
	if sysPx := systemProxyURL(); sysPx != nil {
		status := detectViaProxy(sysPx)
		if status.Error == "" {
			return status
		}
	}
	return detectDirect()
}

// systemProxyURL returns the system HTTP/HTTPS proxy URL by checking the
// standard environment variables, then the WinInet registry on Windows.
func systemProxyURL() *url.URL {
	// Standard env vars (set by most proxy clients including lux itself)
	for _, env := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := os.Getenv(env); v != "" {
			if u, err := url.Parse(v); err == nil && u.Host != "" {
				// Skip loopback — that IS lux, not an upstream proxy
				host, _, _ := net.SplitHostPort(u.Host)
				if host == "" {
					host = u.Host
				}
				if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
					continue
				}
				if strings.EqualFold(host, "localhost") {
					continue
				}
				return u
			}
		}
	}
	return nil
}

// detectViaProxy tunnels the TLS probe through an HTTP CONNECT proxy.
// It tries several probe hosts since some proxies whitelist specific domains.
func detectViaProxy(proxyURL *url.URL) BumpStatus {
	// Try multiple probe targets — some proxies whitelist specific domains
	// (e.g. Apple captive portal, Windows connectivity check) to avoid
	// interference. We try several to increase detection reliability.
	probeTargets := []string{
		"github.com",
		"www.google.com",
		"www.microsoft.com",
		"captive.apple.com",
	}

	for _, host := range probeTargets {
		status := probeViaProxy(proxyURL, host)
		if status.Error != "" {
			// 407 auth required — report and stop
			if strings.Contains(status.Error, "407") {
				return BumpStatus{Error: "proxy requires authentication (407) — SSL inspection check requires credentials"}
			}
			continue
		}
		if status.Detected {
			return status
		}
	}
	return BumpStatus{Detected: false}
}

func probeViaProxy(proxyURL *url.URL, targetHost string) BumpStatus {
	target := net.JoinHostPort(targetHost, "443")
	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		proxyAddr = net.JoinHostPort(proxyAddr, "8080")
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 8*time.Second)
	if err != nil {
		return BumpStatus{Error: fmt.Sprintf("proxy dial failed: %v", err)}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	// Send HTTP CONNECT
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: target},
		Host:   target,
		Header: make(http.Header),
	}
	req.Header.Set("User-Agent", "lux-ssl-probe/1.0")
	// Add proxy auth if present
	if proxyURL.User != nil {
		user := proxyURL.User.Username()
		pass, _ := proxyURL.User.Password()
		if user != "" {
			creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
			req.Header.Set("Proxy-Authorization", "Basic "+creds)
		}
	}
	if err := req.Write(conn); err != nil {
		return BumpStatus{Error: fmt.Sprintf("CONNECT write failed: %v", err)}
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return BumpStatus{Error: fmt.Sprintf("CONNECT response failed: %v", err)}
	}
	if resp.StatusCode == 407 {
		return BumpStatus{Error: fmt.Sprintf("407 proxy auth required")}
	}
	if resp.StatusCode != 200 {
		return BumpStatus{Error: fmt.Sprintf("CONNECT returned %d", resp.StatusCode)}
	}

	return probeTLSChain(conn, targetHost)
}

// detectDirect connects directly to the probe host without a proxy.
func detectDirect() BumpStatus {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(probeHost, probePort), 8*time.Second)
	if err != nil {
		return BumpStatus{Error: fmt.Sprintf("dial failed: %v", err)}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	return probeTLSChain(conn, probeHost)
}

// probeTLSChain performs the TLS handshake on an already-connected TCP conn
// and checks for an unexpected root CA in the chain.
func probeTLSChain(conn net.Conn, targetHost string) BumpStatus {
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		systemRoots = x509.NewCertPool()
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         targetHost,
		InsecureSkipVerify: true, //nolint:gosec
	})
	if err := tlsConn.Handshake(); err != nil {
		return BumpStatus{Error: fmt.Sprintf("tls handshake failed: %v", err)}
	}
	chain := tlsConn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return BumpStatus{Error: "empty certificate chain"}
	}

	// Collect fingerprints of certs the system already trusts
	systemFingerprints := map[string]bool{}
	if verifiedChains, verErr := chain[0].Verify(x509.VerifyOptions{
		DNSName: probeHost,
		Roots:   systemRoots,
	}); verErr == nil {
		for _, ch := range verifiedChains {
			for _, c := range ch {
				h := sha256.Sum256(c.Raw)
				systemFingerprints[hex.EncodeToString(h[:])] = true
			}
		}
	}

	// The last cert in the chain is the root/near-root the proxy is presenting
	interceptRoot := chain[len(chain)-1]
	rootFP := sha256.Sum256(interceptRoot.Raw)
	rootFPHex := hex.EncodeToString(rootFP[:])

	if !systemFingerprints[rootFPHex] {
		return BumpStatus{
			Detected:    true,
			InterceptCA: interceptRoot.Raw,
		}
	}
	return BumpStatus{Detected: false}
}
