package routes

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"unicode/utf8"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// CertCheckResult describes the TLS interceptor (if any) seen through a proxy.
type CertCheckResult struct {
	Intercepted bool   `json:"intercepted"`
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	NotBefore   string `json:"notBefore"`
	NotAfter    string `json:"notAfter"`
	SHA256      string `json:"sha256"`
	PEM         string `json:"pem"`
	Error       string `json:"error,omitempty"`
}


// toLatin1UTF8 re-decodes a string that contains raw Latin-1 bytes as proper UTF-8.
// Older CA certs (common in Brazil) store accented characters as ISO-8859-1.
func toLatin1UTF8(s string) string {
if utf8.ValidString(s) {
return s
}
runes := make([]rune, len(s))
for i := 0; i < len(s); i++ {
runes[i] = rune(s[i])
}
return string(runes)
}

// certIssuerName returns a human-readable name from a cert's issuer,
// preferring Organization over CommonName, with Latin-1 handling.
func certIssuerName(name pkix.Name) string {
parts := []string{}
if len(name.Organization) > 0 {
parts = append(parts, "O="+toLatin1UTF8(name.Organization[0]))
}
if name.CommonName != "" {
parts = append(parts, "CN="+toLatin1UTF8(name.CommonName))
}
if len(parts) > 0 {
return strings.Join(parts, ", ")
}
return toLatin1UTF8(name.String())
}
// checkCert connects through the configured proxy to capture the Squid MITM
// certificate. The target host for CONNECT doesn't matter — Squid presents
// its own TLS bump cert in the handshake regardless of destination. We try
// several targets in order until one gets a 200 from the proxy; the actual
// destination never needs to be reachable.
//
// POST /proxies/check-cert
// Body: {"server": "10.8.0.1", "port": 8082, "username": "...", "password": "..."}
func checkCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server   string `json:"server"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("invalid request body"))
		return
	}

	if req.Server == "" || req.Port == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("server and port required"))
		return
	}

	proxyAddr := fmt.Sprintf("%s:%d", req.Server, req.Port)

	// Try targets in order. The CONNECT destination doesn't need to be reachable
	// — we only need Squid to accept the CONNECT (return 200) so we can do the
	// TLS handshake and see Squid's MITM cert. Use credentials on every attempt.
	targets := []string{
		"example.com:443",        // IANA reserved — almost always allowed
		"1.1.1.1:443",            // Cloudflare IP — bypasses DNS, widely allowed
		"www.google.com:443",     // common fallback
		"www.microsoft.com:443",  // another common fallback
	}

	var lastErr string
	for _, target := range targets {
		result := probeCert(proxyAddr, target, req.Username, req.Password)
		if result == nil {
			lastErr = "connection failed"
			continue
		}
		if result.Error != "" && (strings.Contains(result.Error, "407") || strings.Contains(result.Error, "403")) {
			// Auth rejected — stop trying, credentials are wrong
			render.JSON(w, r, CertCheckResult{Error: result.Error})
			return
		}
		if result.Error != "" {
			lastErr = result.Error
			continue
		}
		// Got a result (intercepted or not)
		render.JSON(w, r, result)
		return
	}

	render.JSON(w, r, CertCheckResult{Error: "could not establish CONNECT tunnel through proxy: " + lastErr})
}

// probeCert connects through a proxy to testHost and checks if the cert is MITM'd.
// Returns nil if the connection failed (so caller can try next host).
func probeCert(proxyAddr, testHost, username, password string) *CertCheckResult {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Determine SNI from testHost
	sni := testHost
	if host, _, err := net.SplitHostPort(testHost); err == nil {
		sni = host
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", testHost, testHost)
	if username != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq += "Proxy-Authorization: Basic " + auth + "\r\n"
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		// 407 = needs auth, skip this host
		return &CertCheckResult{Error: fmt.Sprintf("proxy returned %d", resp.StatusCode)}
	}

	conn.SetReadDeadline(time.Time{})
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil
	}
	defer tlsConn.Close()

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	leaf := certs[0]
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		systemRoots = x509.NewCertPool()
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       sni,
		Roots:         systemRoots,
		Intermediates: intermediates,
	})

	if verifyErr == nil {
		return &CertCheckResult{Intercepted: false, Issuer: leaf.Issuer.CommonName, Subject: leaf.Subject.CommonName}
	}

	// MITM detected
	var issuingCA *x509.Certificate
	if len(certs) > 1 {
		issuingCA = certs[len(certs)-1]
	} else {
		issuingCA = leaf
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuingCA.Raw})
	fingerprint := sha256.Sum256(issuingCA.Raw)

	log.Infoln("[check-cert] MITM detected via %s: issuer=%s", testHost, issuingCA.Issuer.CommonName)

	return &CertCheckResult{
		Intercepted: true,
		Issuer:      issuingCA.Issuer.CommonName,
		Subject:     issuingCA.Subject.CommonName,
		NotBefore:   issuingCA.NotBefore.Format("2006-01-02"),
		NotAfter:    issuingCA.NotAfter.Format("2006-01-02"),
		SHA256:      fmt.Sprintf("%x", fingerprint),
		PEM:         string(pemBlock),
	}
}
