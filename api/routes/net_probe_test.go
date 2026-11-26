package routes

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, dnsNames []string, ipAddrs []net.IP) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "lux-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, pool
}

func startTLSListener(t *testing.T, cert tls.Certificate) (addr string, closeFn func()) {
	t.Helper()
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func startPlainTCPListener(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				// Simulates a captive portal accepting TCP/443 and returning HTTP/closing
				_, _ = conn.Write([]byte("HTTP/1.1 302 Found\r\nLocation: http://portal/\r\n\r\n"))
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func closedTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestProbeDirect_200ExactMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(portalBodyMac + "\n"))
	}))
	defer srv.Close()

	tlsCalled := false
	res := probeDirectWithConfig(directProbeConfig{
		portalURL:       srv.URL,
		expectedBody:    portalBodyMac,
		directTLSTarget: closedTCPAddr(t),
		httpTimeout:     time.Second,
		tlsTimeout:      200 * time.Millisecond,
		dialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != strings.TrimPrefix(srv.URL, "http://") {
				tlsCalled = true
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	})
	if res.State != directOK {
		t.Fatalf("got state=%s, want %s (err=%v)", res.State, directOK, res.Err)
	}
	if tlsCalled {
		t.Fatalf("expected HTTP-first 200 exact match to return without probing TLS 443")
	}
}

func TestProbeDirect_302RedirectAndBlocked443(t *testing.T) {
	const loginURL = "http://airport-wifi.local/login?next=1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", loginURL)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	res := probeDirectWithConfig(directProbeConfig{
		portalURL:       srv.URL,
		expectedBody:    portalBodyMac,
		directTLSTarget: closedTCPAddr(t),
		httpTimeout:     time.Second,
		tlsTimeout:      200 * time.Millisecond,
		dialContext:     (&net.Dialer{}).DialContext,
	})
	if res.State != captivePortal {
		t.Fatalf("got state=%s, want %s", res.State, captivePortal)
	}
	if res.RedirectURL != loginURL {
		t.Fatalf("got RedirectURL=%q, want %q", res.RedirectURL, loginURL)
	}
}

// Regression test (Opus 5.5 High): captive portals often accept raw TCP/443 or
// present an untrusted portal TLS certificate. Anti-spoof MUST require verified
// TLS for 1.1.1.1, so TCP-intercepted or untrusted-cert 443 still reports captivePortal.
func TestProbeDirect_302RedirectAndIntercepted443_StillCaptivePortal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://hotel.portal/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	// Subcase A: port 443 accepts raw TCP and writes plaintext redirect.
	plainAddr, stopPlain := startPlainTCPListener(t)
	defer stopPlain()
	resA := probeDirectWithConfig(directProbeConfig{
		portalURL:       srv.URL,
		expectedBody:    portalBodyMac,
		directTLSTarget: plainAddr,
		tlsServerName:   "1.1.1.1",
		httpTimeout:     time.Second,
		tlsTimeout:      300 * time.Millisecond,
		dialContext:     (&net.Dialer{}).DialContext,
	})
	if resA.State != captivePortal {
		t.Fatalf("plain-TCP intercepted 443 should be captivePortal, got %s", resA.State)
	}

	// Subcase B: port 443 presents an untrusted portal TLS cert.
	bogusCert, _ := generateTestCert(t, []string{"portal.hotel.local"}, nil)
	_, trustedPool := generateTestCert(t, nil, []net.IP{net.ParseIP("1.1.1.1")})
	tlsAddr, stopTLS := startTLSListener(t, bogusCert)
	defer stopTLS()
	resB := probeDirectWithConfig(directProbeConfig{
		portalURL:       srv.URL,
		expectedBody:    portalBodyMac,
		directTLSTarget: tlsAddr,
		tlsServerName:   "1.1.1.1",
		tlsRootCAs:      trustedPool,
		httpTimeout:     time.Second,
		tlsTimeout:      300 * time.Millisecond,
		dialContext:     (&net.Dialer{}).DialContext,
	})
	if resB.State != captivePortal {
		t.Fatalf("untrusted-cert intercepted 443 should be captivePortal, got %s", resB.State)
	}
}

func TestProbeDirect_200SplashHTMLAndBlocked443(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><h1>Hotel Wi-Fi Sign In</h1></body></html>"))
	}))
	defer srv.Close()

	res := probeDirectWithConfig(directProbeConfig{
		portalURL:       srv.URL,
		expectedBody:    portalBodyWin,
		directTLSTarget: closedTCPAddr(t),
		httpTimeout:     time.Second,
		tlsTimeout:      200 * time.Millisecond,
		dialContext:     (&net.Dialer{}).DialContext,
	})
	if res.State != captivePortal {
		t.Fatalf("got state=%s, want %s", res.State, captivePortal)
	}
}

func TestProbeDirect_302RedirectAndVerifiedTLS443_AntiSpoof(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://rogue-hotspot.example/spoof")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	validCert, pool := generateTestCert(t, nil, []net.IP{net.ParseIP("1.1.1.1")})
	valid443, close443 := startTLSListener(t, validCert)
	defer close443()

	res := probeDirectWithConfig(directProbeConfig{
		portalURL:       srv.URL,
		expectedBody:    portalBodyMac,
		directTLSTarget: valid443,
		tlsServerName:   "1.1.1.1",
		tlsRootCAs:      pool,
		httpTimeout:     time.Second,
		tlsTimeout:      400 * time.Millisecond,
		dialContext:     (&net.Dialer{}).DialContext,
	})
	if res.State != directOK {
		t.Fatalf("anti-spoof guard failed: got state=%s, want %s", res.State, directOK)
	}
}

func TestProbeDirect_200SplashHTMLAndVerifiedTLS443_AntiSpoof(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>spoofed splash</html>"))
	}))
	defer srv.Close()

	validCert, pool := generateTestCert(t, nil, []net.IP{net.ParseIP("1.1.1.1")})
	valid443, close443 := startTLSListener(t, validCert)
	defer close443()

	res := probeDirectWithConfig(directProbeConfig{
		portalURL:       srv.URL,
		expectedBody:    portalBodyMac,
		directTLSTarget: valid443,
		tlsServerName:   "1.1.1.1",
		tlsRootCAs:      pool,
		httpTimeout:     time.Second,
		tlsTimeout:      400 * time.Millisecond,
		dialContext:     (&net.Dialer{}).DialContext,
	})
	if res.State != directOK {
		t.Fatalf("anti-spoof guard failed on splash HTML: got state=%s, want %s", res.State, directOK)
	}
}

func TestProbeDirect_511AndBlocked443(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNetworkAuthenticationRequired)
	}))
	defer srv.Close()

	res := probeDirectWithConfig(directProbeConfig{
		portalURL:       srv.URL,
		expectedBody:    portalBodyMac,
		directTLSTarget: closedTCPAddr(t),
		httpTimeout:     time.Second,
		tlsTimeout:      200 * time.Millisecond,
		dialContext:     (&net.Dialer{}).DialContext,
	})
	if res.State != captivePortal {
		t.Fatalf("got state=%s, want %s", res.State, captivePortal)
	}
}

func TestProbeDirect_TimeoutAndBlocked443_NoInternet(t *testing.T) {
	blockCh := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-blockCh:
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(blockCh)
		srv.Close()
	}()

	res := probeDirectWithConfig(directProbeConfig{
		portalURL:       srv.URL,
		expectedBody:    portalBodyMac,
		directTLSTarget: closedTCPAddr(t),
		httpTimeout:     120 * time.Millisecond,
		tlsTimeout:      120 * time.Millisecond,
		dialContext:     (&net.Dialer{}).DialContext,
	})
	if res.State != noInternet {
		t.Fatalf("got state=%s, want %s", res.State, noInternet)
	}
}

func TestProbeDirect_HTTPErrorFallsBackToVerifiedTLS443(t *testing.T) {
	validCert, pool := generateTestCert(t, nil, []net.IP{net.ParseIP("1.1.1.1")})
	valid443, close443 := startTLSListener(t, validCert)
	defer close443()

	res := probeDirectWithConfig(directProbeConfig{
		portalURL:       "http://unreachable.invalid/hotspot-detect.html",
		expectedBody:    portalBodyMac,
		directTLSTarget: valid443,
		tlsServerName:   "1.1.1.1",
		tlsRootCAs:      pool,
		httpTimeout:     150 * time.Millisecond,
		tlsTimeout:      400 * time.Millisecond,
		dialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == valid443 {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}
			return nil, errors.New("dns failure")
		},
	})
	if res.State != directOK {
		t.Fatalf("expected verified TLS 443 fallback to return directOK, got %s", res.State)
	}
}

func TestProbeProxy_TLS200_407Auth_RejectsSpoofed200AndBare407(t *testing.T) {
	appleCert, applePool := generateTestCert(t, []string{"captive.apple.com"}, nil)
	wrongHostCert, _ := generateTestCert(t, []string{"rogue.hotel.local"}, nil)

	startMockProxy := func(handler func(net.Conn)) (string, int, func()) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					br := bufio.NewReader(conn)
					for {
						line, err := br.ReadString('\n')
						if err != nil || line == "\r\n" {
							break
						}
					}
					handler(conn)
				}(c)
			}
		}()
		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := strconv.Atoi(portStr)
		return host, port, func() { _ = ln.Close() }
	}

	// 1. 200 OK + valid TLS for captive.apple.com -> Alive=true.
	h, p, stop := startMockProxy(func(c net.Conn) {
		_, _ = fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{appleCert}})
		_ = tc.Handshake()
	})
	res := probeProxyWithTLS(h, p, "u", "p", applePool)
	stop()
	if !res.Alive {
		t.Fatalf("200 + valid TLS: want Alive=true, got false (err=%v)", res.Err)
	}

	// 2. 200 OK + untrusted corporate SSL-bump cert for captive.apple.com -> Alive=true.
	h, p, stop = startMockProxy(func(c net.Conn) {
		_, _ = fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{appleCert}})
		_ = tc.Handshake()
	})
	emptyPool := x509.NewCertPool()
	res = probeProxyWithTLS(h, p, "u", "p", emptyPool)
	stop()
	if !res.Alive {
		t.Fatalf("200 + SSL-bump UnknownAuthorityError for matching host: want Alive=true, got false (err=%v)", res.Err)
	}

	// 3. 200 OK + spoofed plaintext HTML (no TLS) -> Alive=false.
	h, p, stop = startMockProxy(func(c net.Conn) {
		_, _ = fmt.Fprint(c, "HTTP/1.1 200 OK\r\n\r\n<html>Hotel Wi-Fi</html>")
	})
	res = probeProxyWithTLS(h, p, "u", "p", applePool)
	stop()
	if res.Alive {
		t.Fatalf("200 + plaintext HTML spoof: want Alive=false, got true")
	}

	// 4. 200 OK + wrong hostname TLS cert -> Alive=false.
	h, p, stop = startMockProxy(func(c net.Conn) {
		_, _ = fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{wrongHostCert}})
		_ = tc.Handshake()
	})
	res = probeProxyWithTLS(h, p, "u", "p", applePool)
	stop()
	if res.Alive {
		t.Fatalf("200 + wrong hostname cert: want Alive=false, got true")
	}

	// 5. 407 with Proxy-Authenticate header -> Alive=true.
	h, p, stop = startMockProxy(func(c net.Conn) {
		_, _ = fmt.Fprint(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Squid\"\r\n\r\n")
	})
	res = probeProxyWithTLS(h, p, "u", "p", applePool)
	stop()
	if !res.Alive {
		t.Fatalf("407 with Proxy-Authenticate: want Alive=true, got false (err=%v)", res.Err)
	}

	// 6. Bare 407 without Proxy-Authenticate header -> Alive=false.
	h, p, stop = startMockProxy(func(c net.Conn) {
		_, _ = fmt.Fprint(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
	})
	res = probeProxyWithTLS(h, p, "u", "p", applePool)
	stop()
	if res.Alive {
		t.Fatalf("bare 407 without Proxy-Authenticate: want Alive=false, got true")
	}

	// 7. 502 Bad Gateway -> Alive=false.
	h, p, stop = startMockProxy(func(c net.Conn) {
		_, _ = fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
	})
	res = probeProxyWithTLS(h, p, "u", "p", applePool)
	stop()
	if res.Alive {
		t.Fatalf("502 Bad Gateway: want Alive=false, got true")
	}
}
