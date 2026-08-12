package routes

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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

// checkCert connects through the configured proxy to a well-known HTTPS host and
// inspects the certificate. If the cert is not issued by a publicly trusted CA
// (i.e. it's a corporate MITM cert), it reports the intercepting CA's details.
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
	testHost := "www.google.com:443"

	log.Infoln("[check-cert] connecting through %s to %s", proxyAddr, testHost)

	// Connect to the proxy
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		render.JSON(w, r, CertCheckResult{Error: "cannot reach proxy: " + err.Error()})
		return
	}
	defer conn.Close()

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", testHost, testHost)
	if req.Username != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(req.Username + ":" + req.Password))
		connectReq += "Proxy-Authorization: Basic " + auth + "\r\n"
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		render.JSON(w, r, CertCheckResult{Error: "proxy write failed: " + err.Error()})
		return
	}

	// Read CONNECT response
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		render.JSON(w, r, CertCheckResult{Error: "proxy response error: " + err.Error()})
		return
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		render.JSON(w, r, CertCheckResult{
			Error: fmt.Sprintf("proxy returned %d (auth may be wrong)", resp.StatusCode),
		})
		return
	}

	// TLS handshake through the tunnel — DON'T skip verify, we WANT to see
	// what cert the proxy presents
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "www.google.com",
		InsecureSkipVerify: true, // we'll verify ourselves below
	})
	if err := tlsConn.Handshake(); err != nil {
		render.JSON(w, r, CertCheckResult{Error: "TLS handshake failed: " + err.Error()})
		return
	}
	defer tlsConn.Close()

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		render.JSON(w, r, CertCheckResult{Error: "no certificate presented"})
		return
	}

	leaf := certs[0]

	// Check if the leaf is signed by a publicly trusted CA
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		systemRoots = x509.NewCertPool()
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       "www.google.com",
		Roots:         systemRoots,
		Intermediates: intermediates,
	})

	if verifyErr == nil {
		// Cert is publicly trusted — no interception
		render.JSON(w, r, CertCheckResult{
			Intercepted: false,
			Issuer:      leaf.Issuer.CommonName,
			Subject:     leaf.Subject.CommonName,
		})
		return
	}

	// Certificate is NOT publicly trusted — this is a corporate MITM cert.
	// Find the issuing CA (last cert in the chain, or the leaf's issuer)
	var issuingCA *x509.Certificate
	if len(certs) > 1 {
		issuingCA = certs[len(certs)-1]
	} else {
		issuingCA = leaf
	}

	// Encode the CA cert as PEM for the client to install
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuingCA.Raw,
	})

	fingerprint := sha256.Sum256(issuingCA.Raw)

	log.Infoln("[check-cert] MITM cert detected: issuer=%s subject=%s",
		issuingCA.Issuer.CommonName, issuingCA.Subject.CommonName)

	render.JSON(w, r, CertCheckResult{
		Intercepted: true,
		Issuer:      issuingCA.Issuer.CommonName,
		Subject:     issuingCA.Subject.CommonName,
		NotBefore:   issuingCA.NotBefore.Format("2006-01-02"),
		NotAfter:    issuingCA.NotAfter.Format("2006-01-02"),
		SHA256:      fmt.Sprintf("%x", fingerprint),
		PEM:         string(pemBlock),
	})
}
