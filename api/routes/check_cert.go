package routes

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	"github.com/igoogolx/itun2socks/pkg/log"
)

var (
	extraRootsMu  sync.RWMutex
	extraRootsPEM []byte
)

// AddExtraRoot appends PEM certificate bytes to in-memory roots so newly installed
// certificates are recognized immediately without restarting lux_core.
func AddExtraRoot(pemBytes []byte) {
	extraRootsMu.Lock()
	defer extraRootsMu.Unlock()
	extraRootsPEM = append(extraRootsPEM, append([]byte("\n"), pemBytes...)...)
}

// CertCheckResult describes the TLS interceptor (if any) seen through a proxy.
// Intercepted is true ONLY when an UNTRUSTED MITM CA is detected (so the UI
// prompts the user to trust it). BumpDetected is true whenever SSL interception
// is present — whether untrusted OR already trusted in the OS root store — so
// the UI can still extract the organization name from Issuer cleanly.
type CertCheckResult struct {
	Intercepted  bool   `json:"intercepted"`
	BumpDetected bool   `json:"bumpDetected"`
	Issuer       string `json:"issuer"`
	Subject      string `json:"subject"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
	SHA256       string `json:"sha256"`
	PEM          string `json:"pem"`
	Error        string `json:"error,omitempty"`
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

// isCertInSystemStore checks if the certificate is already present in the OS root store.
// Target Store: Cert:\LocalMachine\Root (Windows) or System.keychain (macOS).
func isCertInSystemStore(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	sha1Bytes := sha1.Sum(cert.Raw)
	sha1Thumbprint := strings.ToUpper(hex.EncodeToString(sha1Bytes[:]))

	if runtime.GOOS == "windows" {
		cmd := exec.Command("certutil.exe", "-verifystore", "Root", sha1Thumbprint)
		if err := cmd.Run(); err == nil {
			return true
		}
		psCmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
			fmt.Sprintf("(Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.Thumbprint -eq '%s' }).Count", sha1Thumbprint))
		if out, err := psCmd.Output(); err == nil {
			trimmed := strings.TrimSpace(string(out))
			if trimmed != "" && trimmed != "0" {
				return true
			}
		}
		return false
	} else if runtime.GOOS == "darwin" {
		cmd := exec.Command("/usr/bin/security", "find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain")
		if out, err := cmd.Output(); err == nil {
			if strings.Contains(strings.ToUpper(string(out)), sha1Thumbprint) {
				return true
			}
		}
	}
	return false
}

// fetchDirectCA fetches the CA certificate directly from the upstream proxy host
// via plain HTTP, explicitly disabling any HTTP proxy to prevent chicken-and-egg interception.
// Primary: http://<proxy_host>/root-ca
// Fallback: http://<proxy_host>:9876/download/cas (proxy-worker API)
func fetchDirectCA(proxyHost string) (*x509.Certificate, []byte, error) {
	host := proxyHost
	port := ""
	if h, p, err := net.SplitHostPort(proxyHost); err == nil {
		host = h
		port = p
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil, // NEVER use proxy for CA retrieval
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			ResponseHeaderTimeout: 5 * time.Second,
			DisableKeepAlives:     true,
		},
		Timeout: 8 * time.Second,
	}

	urls := []string{
		fmt.Sprintf("http://%s/root-ca", host),
	}
	if port != "" && port != "80" && port != "9876" {
		urls = append(urls, fmt.Sprintf("http://%s:%s/root-ca", host, port))
	}
	urls = append(urls, fmt.Sprintf("http://%s:9876/download/cas", host))

	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("endpoint %s returned HTTP %d", u, resp.StatusCode)
			continue
		}
		if len(body) == 0 {
			lastErr = fmt.Errorf("endpoint %s returned empty body", u)
			continue
		}

		// Try parsing as PEM
		var certs []*x509.Certificate
		var pemBytes []byte
		rest := body
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				c, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					certs = append(certs, c)
					pemBytes = append(pemBytes, pem.EncodeToMemory(block)...)
				}
			}
		}

		// If not PEM, try parsing as raw DER
		if len(certs) == 0 {
			parsed, err := x509.ParseCertificates(body)
			if err == nil && len(parsed) > 0 {
				certs = parsed
				for _, c := range certs {
					pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
					pemBytes = append(pemBytes, pemBlock...)
				}
			}
		}

		if len(certs) > 0 {
			// Find root CA (self-signed or last in chain)
			targetCA := certs[len(certs)-1]
			for _, c := range certs {
				if c.CheckSignatureFrom(c) == nil {
					targetCA = c
					break
				}
			}
			log.Infoln("[check-cert] Successfully retrieved CA from %s (subject: %s)", u, targetCA.Subject.CommonName)
			return targetCA, pemBytes, nil
		}
		lastErr = fmt.Errorf("endpoint %s returned no valid certificates", u)
	}

	return nil, nil, fmt.Errorf("could not fetch CA from endpoints: %v", lastErr)
}

// checkCert connects through the configured proxy to capture the Squid MITM
// certificate. The target host for CONNECT doesn't matter — Squid presents
// its own TLS bump cert in the handshake regardless of destination. We try
// several targets in order until one gets a 200 from the proxy.
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

	targets := []string{
		"example.com:443",       // IANA reserved — almost always allowed
		"1.1.1.1:443",           // Cloudflare IP — bypasses DNS, widely allowed
		"www.google.com:443",    // common fallback
		"www.microsoft.com:443", // another common fallback
	}

	var lastErr string
	for _, target := range targets {
		result, dialFailed := probeCert(proxyAddr, target, req.Username, req.Password)
		if dialFailed {
			// Proxy TCP address itself is unreachable on all interfaces — no point
			// repeating the same timeout across 4 targets.
			lastErr = "connection failed"
			break
		}
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

// fetchRootCA handles direct CA retrieval without requiring a full TLS probe.
//
// POST /proxies/fetch-root-ca
// Body: {"host": "10.8.0.1"}
func fetchRootCA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil || req.Host == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("host is required"))
		return
	}

	ca, pemBytes, err := fetchDirectCA(req.Host)
	if err != nil {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, NewError(fmt.Sprintf("Could not reach the proxy certificate endpoint at http://%s/root-ca. Verify your local network connection.", req.Host)))
		return
	}

	installed := isCertInSystemStore(ca)
	fingerprint := sha256.Sum256(ca.Raw)
	render.JSON(w, r, render.M{
		"success":   true,
		"installed": installed,
		"pem":       string(pemBytes),
		"issuer":    certIssuerName(ca.Issuer),
		"subject":   certIssuerName(ca.Subject),
		"notBefore": ca.NotBefore.Format("2006-01-02"),
		"notAfter":  ca.NotAfter.Format("2006-01-02"),
		"sha256":    fmt.Sprintf("%x", fingerprint),
	})
}

// dialProxyReachable connects to proxyAddr, trying the OS default route first
// and falling back to active non-TUN physical interfaces in parallel (e.g. a
// multi-homed laptop with Ethernet as default route plus corporate Wi-Fi where
// the detected proxy lives).
func dialProxyReachable(proxyAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 2500*time.Millisecond)
	if err == nil {
		return conn, nil
	}

	ifaces, ifErr := net.Interfaces()
	if ifErr != nil {
		return nil, err
	}

	var candidates []string
	for _, nif := range ifaces {
		if nif.Flags&net.FlagUp == 0 || nif.Flags&net.FlagLoopback != 0 {
			continue
		}
		if pac.IsExcludedTunIface(nif.Name) || strings.HasPrefix(nif.Name, "bridge") {
			continue
		}
		// Only try interfaces with a real non-loopback IPv4 address.
		addrs, _ := nif.Addrs()
		hasV4 := false
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				ip4 := ipn.IP.To4()
				if ip4 != nil && !ip4.IsLoopback() && !(ip4[0] == 10 && ip4[1] == 255) && !(ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)) {
					hasV4 = true
					break
				}
			}
		}
		if hasV4 {
			candidates = append(candidates, nif.Name)
		}
	}
	if len(candidates) == 0 {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	type dialRes struct {
		c net.Conn
	}
	ch := make(chan dialRes, len(candidates))
	var wg sync.WaitGroup
	for _, name := range candidates {
		name := name
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, dErr := dialer.DialContext(ctx, "tcp4", proxyAddr, dialer.WithInterface(name))
			if dErr == nil && c != nil {
				select {
				case ch <- dialRes{c: c}:
					cancel()
				default:
					_ = c.Close()
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(ch)
	}()

	if res, ok := <-ch; ok && res.c != nil {
		// Drain any duplicate winner cleanly.
		go func() {
			for extra := range ch {
				if extra.c != nil {
					_ = extra.c.Close()
				}
			}
		}()
		return res.c, nil
	}
	return nil, err
}

// probeCert connects through a proxy to testHost and checks if the cert is MITM'd.
// Returns (nil, true) if TCP connection to the proxy itself failed, or (nil, false)
// if this specific testHost failed and another target should be tried.
func probeCert(proxyAddr, testHost, username, password string) (*CertCheckResult, bool) {
	conn, err := dialProxyReachable(proxyAddr)
	if err != nil {
		return nil, true
	}
	defer conn.Close()

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
		return nil, false
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, false
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return &CertCheckResult{Error: fmt.Sprintf("proxy returned %d", resp.StatusCode)}, false
	}

	conn.SetReadDeadline(time.Time{})
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, false
	}
	defer tlsConn.Close()

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, false
	}

	leaf := certs[0]
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		systemRoots = x509.NewCertPool()
	}

	// 1. Append in-memory dynamically installed certificates (bypasses Go's sync.Once SystemCertPool cache)
	extraRootsMu.RLock()
	if len(extraRootsPEM) > 0 {
		systemRoots.AppendCertsFromPEM(extraRootsPEM)
	}
	extraRootsMu.RUnlock()

	// 2. Append any certificates from proxy_ca_bundle.pem if present on disk
	bundlePath := filepath.Join(constants.Path.HomeDir(), "proxy_ca_bundle.pem")
	if data, err := os.ReadFile(bundlePath); err == nil && len(data) > 0 {
		systemRoots.AppendCertsFromPEM(data)
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	verifiedChains, verifyErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       sni,
		Roots:         systemRoots,
		Intermediates: intermediates,
	})

	if verifyErr == nil {
		bump := isTrustedBumpCert(leaf, verifiedChains, intermediates, sni)
		return &CertCheckResult{
			Intercepted:  false,
			BumpDetected: bump,
			Issuer:       certIssuerName(leaf.Issuer),
			Subject:      certIssuerName(leaf.Subject),
		}, false
	}

	// Leaf verification failed — attempt direct CA retrieval from upstream proxy host
	// Primary: http://<proxy_host>/root-ca
	// Fallback: http://<proxy_host>:9876/download/cas
	proxyHost := proxyAddr
	if h, _, err := net.SplitHostPort(proxyAddr); err == nil {
		proxyHost = h
	}

	directCA, directPEM, err := fetchDirectCA(proxyHost)
	if err == nil && directCA != nil {
		// Pre-check: If already installed in the system root store, do not show prompt / mark healthy
		if isCertInSystemStore(directCA) {
			log.Infoln("[check-cert] Root CA (%s) is already installed in system store", directCA.Subject.CommonName)
			AddExtraRoot(directPEM)
			return &CertCheckResult{
				Intercepted:  false,
				BumpDetected: true,
				Issuer:       certIssuerName(directCA.Issuer),
				Subject:      certIssuerName(directCA.Subject),
			}, false
		}

		fingerprint := sha256.Sum256(directCA.Raw)
		log.Infoln("[check-cert] Untrusted root CA detected via direct HTTP endpoint: %s", directCA.Subject.CommonName)
		return &CertCheckResult{
			Intercepted:  true,
			BumpDetected: true,
			Issuer:       certIssuerName(directCA.Issuer),
			Subject:      certIssuerName(directCA.Subject),
			NotBefore:    directCA.NotBefore.Format("2006-01-02"),
			NotAfter:     directCA.NotAfter.Format("2006-01-02"),
			SHA256:       fmt.Sprintf("%x", fingerprint),
			PEM:          string(directPEM),
		}, false
	}

	// Fallback 2: Proxy only exposes cert via TLS intercept (extract from handshake)
	var issuingCA *x509.Certificate
	if len(certs) > 1 {
		issuingCA = certs[len(certs)-1]
	} else {
		issuingCA = leaf
	}

	// Pre-check for handshake cert against OS root store
	if isCertInSystemStore(issuingCA) {
		log.Infoln("[check-cert] Handshake CA (%s) is already installed in system store", issuingCA.Subject.CommonName)
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuingCA.Raw})
		AddExtraRoot(pemBlock)
		return &CertCheckResult{
			Intercepted:  false,
			BumpDetected: true,
			Issuer:       certIssuerName(issuingCA.Issuer),
			Subject:      certIssuerName(issuingCA.Subject),
		}, false
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuingCA.Raw})
	fingerprint := sha256.Sum256(issuingCA.Raw)

	log.Infoln("[check-cert] Direct CA fetch failed (%v); MITM detected via %s TLS handshake: issuer=%s", err, testHost, issuingCA.Issuer.CommonName)

	return &CertCheckResult{
		Intercepted:  true,
		BumpDetected: true,
		Issuer:       certIssuerName(issuingCA.Issuer),
		Subject:      certIssuerName(issuingCA.Subject),
		NotBefore:    issuingCA.NotBefore.Format("2006-01-02"),
		NotAfter:     issuingCA.NotAfter.Format("2006-01-02"),
		SHA256:       fmt.Sprintf("%x", fingerprint),
		PEM:          string(pemBlock),
	}, false
}
