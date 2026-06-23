package ssl_inspect

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
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

// Detect probes captive.apple.com via a direct TLS connection and checks
// whether the certificate chain contains an unexpected root CA, which
// indicates SSL bumping / interception.
func Detect() BumpStatus {
	return detectTLS("", "")
}

// DetectViaProxy probes through an HTTP CONNECT proxy (host:port or user:pass@host:port).
// This is needed when the direct connection doesn't go through the upstream proxy.
func DetectViaProxy(proxyAddr string) BumpStatus {
	return detectTLS(proxyAddr, "")
}

func detectTLS(proxyAddr, _ string) BumpStatus {
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		systemRoots = x509.NewCertPool()
	}

	var rawConn net.Conn
	target := net.JoinHostPort(probeHost, probePort)

	if proxyAddr != "" {
		// Connect through HTTP proxy via CONNECT
		rawConn, err = net.DialTimeout("tcp", proxyAddr, 8*time.Second)
		if err != nil {
			return BumpStatus{Error: fmt.Sprintf("dial proxy failed: %v", err)}
		}
		// Send HTTP CONNECT
		rawConn.SetDeadline(time.Now().Add(8 * time.Second))
		fmt.Fprintf(rawConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		// Read response (may be 200, 407, etc.)
		buf := make([]byte, 512)
		n, readErr := rawConn.Read(buf)
		if readErr != nil {
			rawConn.Close()
			return BumpStatus{Error: fmt.Sprintf("read proxy response failed: %v", readErr)}
		}
		resp := string(buf[:n])
		if len(resp) < 12 || resp[:12] != "HTTP/1.1 200" && resp[:12] != "HTTP/1.0 200" {
			rawConn.Close()
			// 407 = auth required — can't probe without credentials
			if len(resp) > 12 && resp[9:12] == "407" {
				return BumpStatus{Error: "407"}
			}
			return BumpStatus{Error: fmt.Sprintf("proxy CONNECT failed: %s", resp[:min(len(resp), 64)])}
		}
	} else {
		rawConn, err = net.DialTimeout("tcp", target, 8*time.Second)
		if err != nil {
			return BumpStatus{Error: fmt.Sprintf("dial failed: %v", err)}
		}
	}
	defer rawConn.Close()

	// TLS handshake
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         probeHost,
		InsecureSkipVerify: true, //nolint:gosec
	})
	_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return BumpStatus{Error: fmt.Sprintf("tls handshake failed: %v", err)}
	}
	chain := tlsConn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return BumpStatus{Error: "empty certificate chain"}
	}

	// Collect fingerprints from the verified (trusted) chain
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

	// The last cert presented is the root/near-root of the intercepting chain
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
