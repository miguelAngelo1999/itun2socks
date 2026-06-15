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
// indicates SSL bumping / HTTPS interception.
func Detect() BumpStatus {
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		systemRoots = x509.NewCertPool()
	}

	rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(probeHost, probePort), 8*time.Second)
	if err != nil {
		return BumpStatus{Error: fmt.Sprintf("dial failed: %v", err)}
	}
	defer rawConn.Close()

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

	interceptRoot := chain[len(chain)-1]
	rootFP := sha256.Sum256(interceptRoot.Raw)
	if !systemFingerprints[hex.EncodeToString(rootFP[:])] {
		return BumpStatus{Detected: true, InterceptCA: interceptRoot.Raw}
	}
	return BumpStatus{Detected: false}
}
