package pac

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestExtractProxiesFromPAC_DynamicEvalAndCommentsAndSocks(t *testing.T) {
	js := `
// Old proxy commented out: PROXY 10.99.99.99:8080
/* Multi-line comment:
   PROXY 10.88.88.88:3128
*/
function FindProxyForURL(url, host) {
	var hostPart = "10.8.0." + "1";
	var portPart = 8080 + 2;
	if (dnsDomainIs(host, ".internal.local")) {
		return "DIRECT";
	}
	if (shExpMatch(host, "*.special.org")) {
		return "SOCKS5 10.8.0.5:1080; DIRECT";
	}
	// Loopback must be skipped: PROXY 127.0.0.1:1090
	return "PROXY " + hostPart + ":" + portPart + "; PROXY 10.8.0.2:3128; DIRECT";
}
`
	got := ExtractProxiesFromPAC(js)
	if len(got) != 3 {
		t.Fatalf("expected 3 proxies (dynamic primary + backup + socks5), got %d: %+v", len(got), got)
	}
	// First entry must be the live-evaluated dynamic proxy (10.8.0.1:8082).
	if got[0].Host != "10.8.0.1" || got[0].Port != "8082" || got[0].Type != "http" {
		t.Errorf("expected dynamic evaluated proxy first (10.8.0.1:8082 http), got %+v", got[0])
	}
	hasBackup := false
	hasSocks := false
	for _, p := range got {
		if p.Host == "10.99.99.99" || p.Host == "10.88.88.88" || p.Host == "127.0.0.1" {
			t.Errorf("should never include commented-out or loopback proxy: %+v", p)
		}
		if p.Host == "10.8.0.2" && p.Port == "3128" && p.Type == "http" {
			hasBackup = true
		}
		if p.Host == "10.8.0.5" && p.Port == "1080" && p.Type == "socks5" {
			hasSocks = true
		}
	}
	if !hasBackup || !hasSocks {
		t.Errorf("missing expected backup/socks5 proxy in %+v", got)
	}
}

func TestBuildWPADCandidates(t *testing.T) {
	cands := BuildWPADCandidates(
		[]string{"office.arautos.corp"},
		[]string{"10.8.0.1"},
		[]string{"10.8.0.2"},
	)
	joined := strings.Join(cands, "\n")
	for _, want := range []string{
		"http://wpad/wpad.dat",
		"http://wpad/proxy.pac",
		"http://wpad.office.arautos.corp/wpad.dat",
		"http://wpad.arautos.corp/wpad.dat",
		"http://10.8.0.1/wpad.dat",
		"http://10.8.0.1/proxy.pac",
		"http://10.8.0.2/wpad.dat",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing expected WPAD candidate %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "http://wpad.corp/") {
		t.Errorf("should not walk down to bare 1-label TLD: %s", joined)
	}
}

func TestParseWindowsProxyServer(t *testing.T) {
	// Skip Lux loopback listener
	if got := ParseWindowsProxyServer("127.0.0.1:1090", "os-manual"); len(got) != 0 {
		t.Fatalf("expected loopback to be skipped, got %+v", got)
	}
	// Scheme-qualified WinINET string
	got := ParseWindowsProxyServer("http=10.8.0.1:8082;https=10.8.0.1:8082;socks=10.8.0.5:1080", "os-manual")
	if len(got) != 2 {
		t.Fatalf("expected 2 deduplicated entries (http + socks5), got %+v", got)
	}
	if got[0].Host != "10.8.0.1" || got[0].Port != "8082" || got[0].Type != "http" {
		t.Errorf("unexpected first entry: %+v", got[0])
	}
	if got[1].Host != "10.8.0.5" || got[1].Port != "1080" || got[1].Type != "socks5" {
		t.Errorf("unexpected second entry: %+v", got[1])
	}
}

func TestLooksLikePACScript(t *testing.T) {
	if !LooksLikePACScript(`function FindProxyForURL(url, host) { return "DIRECT"; }`) {
		t.Error("expected valid PAC script to be accepted")
	}
	if LooksLikePACScript(`<!DOCTYPE html><html><body>Router Login FindProxyForURL</body></html>`) {
		t.Error("expected HTML page to be rejected")
	}
	if LooksLikePACScript(`hello`) {
		t.Error("expected short non-PAC text to be rejected")
	}
}

func TestProbeHTTPProxyPort_AcceptsProxyRejectsRouterHTML(t *testing.T) {
	startMock := func(response string) (int, func()) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
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
					buf := make([]byte, 512)
					_, _ = conn.Read(buf)
					_, _ = fmt.Fprint(conn, response)
				}(c)
			}
		}()
		return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
	}

	// 1. Squid 407 Proxy Auth Required -> MUST match
	p407, close407 := startMock("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Squid\"\r\n\r\n")
	defer close407()
	if !probeHTTPProxyPort("127.0.0.1", p407, time.Second) {
		t.Error("expected 407 proxy to be detected")
	}

	// 2. Open CONNECT 200 Connection established -> MUST match
	p200, close200 := startMock("HTTP/1.1 200 Connection established\r\n\r\n")
	defer close200()
	if !probeHTTPProxyPort("127.0.0.1", p200, time.Second) {
		t.Error("expected 200 Connection established proxy to be detected")
	}

	// 3. Home router HTML admin panel -> MUST reject
	pHTML, closeHTML := startMock("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html>Router</html>")
	defer closeHTML()
	if probeHTTPProxyPort("127.0.0.1", pHTML, time.Second) {
		t.Error("expected HTML router page to be rejected")
	}
}

func TestIsIPHostPACURLAndHostnameWPAD(t *testing.T) {
	if !IsIPHostPACURL("http://10.60.0.1:80/wpad.dat") {
		t.Error("expected IPv4 PAC URL to be flagged as IP host")
	}
	if !IsIPHostPACURL("http://192.168.71.254/proxy.pac") {
		t.Error("expected IPv4 PAC URL without port to be flagged as IP host")
	}
	if IsIPHostPACURL("http://wpad/wpad.dat") {
		t.Error("expected http://wpad/wpad.dat to be recognized as dynamic hostname")
	}
	if IsIPHostPACURL("http://wpad.corp.local/proxy.pac") {
		t.Error("expected http://wpad.corp.local/proxy.pac to be recognized as dynamic hostname")
	}

	hostOnly := BuildHostnameWPADCandidates([]string{"corp.local"})
	for _, u := range hostOnly {
		if IsIPHostPACURL(u) {
			t.Errorf("BuildHostnameWPADCandidates must not return IP URLs: %s", u)
		}
	}
	if len(hostOnly) < 2 || hostOnly[0] != "http://wpad/wpad.dat" || hostOnly[1] != "http://wpad/proxy.pac" {
		t.Errorf("expected http://wpad/wpad.dat & proxy.pac first, got %+v", hostOnly)
	}
}
