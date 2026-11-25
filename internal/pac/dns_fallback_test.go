package pac

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	D "github.com/miekg/dns"
)

func TestGoLookup_SingleLabelWPADViaSystemDNSFallback(t *testing.T) {
	// Start a local UDP DNS server simulating a corporate LAN DNS server
	// (e.g. 10.60.0.1:53) that answers A queries for single-label "wpad."
	// even when the OS native resolver (Windows GetAddrInfoW with empty DNS
	// suffix) refuses to resolve single-label names.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	dnsAddr := pc.LocalAddr().String()

	mux := D.NewServeMux()
	mux.HandleFunc("wpad-unit-test.", func(w D.ResponseWriter, r *D.Msg) {
		m := new(D.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &D.A{
			Hdr: D.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: D.TypeA,
				Class:  D.ClassINET,
				Ttl:    60,
			},
			A: net.IPv4(10, 60, 1, 1),
		})
		_ = w.WriteMsg(m)
	})
	mux.HandleFunc("intranet-unit-test.corp.local.", func(w D.ResponseWriter, r *D.Msg) {
		m := new(D.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &D.A{
			Hdr: D.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: D.TypeA,
				Class:  D.ClassINET,
				Ttl:    60,
			},
			A: net.IPv4(10, 60, 1, 2),
		})
		_ = w.WriteMsg(m)
	})

	srv := &D.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	// Ensure localLookup is nil (simulates System mode / disconnected state).
	SetLocalLookup(nil)
	getDNSCache().Purge()

	systemDNSProviderMu.Lock()
	prevProvider := systemDNSProvider
	systemDNSProvider = func() ([]string, []string) {
		return []string{dnsAddr}, []string{"corp.local"}
	}
	systemDNSProviderMu.Unlock()
	defer func() {
		systemDNSProviderMu.Lock()
		systemDNSProvider = prevProvider
		systemDNSProviderMu.Unlock()
		getDNSCache().Purge()
	}()

	// 1. Direct single-label A-record ("wpad-unit-test" -> 10.60.1.1)
	if got := GoLookup("wpad-unit-test"); got != "10.60.1.1" {
		t.Fatalf("GoLookup(wpad-unit-test) = %q, want 10.60.1.1", got)
	}

	// 2. Single-label via adapter DNS search suffix ("intranet-unit-test" -> 10.60.1.2)
	if got := GoLookup("intranet-unit-test"); got != "10.60.1.2" {
		t.Fatalf("GoLookup(intranet-unit-test) = %q, want 10.60.1.2", got)
	}
}

func TestFetch_SingleLabelWPADViaLocalDNSAndHTTP(t *testing.T) {
	// Serve a minimal PAC file on 127.0.0.1:<port> and map single-label host
	// "wpad-fetch-test" to 127.0.0.1 via SetLocalLookup to verify Fetch dials
	// the resolved IP while preserving Host: wpad-fetch-test.
	const samplePAC = `function FindProxyForURL(url, host) { return "PROXY 10.8.0.1:8082"; }`
	var sawHost string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHost = r.Host
		_, _ = w.Write([]byte(samplePAC))
	}))
	defer ts.Close()

	_, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}

	getDNSCache().Purge()
	getDNSCache().Add("wpad-fetch-test", "127.0.0.1")
	defer getDNSCache().Purge()

	body, err := Fetch("http://wpad-fetch-test:" + port + "/wpad.dat")
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if body != samplePAC {
		t.Fatalf("unexpected PAC body: %q", body)
	}
	if sawHost != "wpad-fetch-test:"+port {
		t.Fatalf("expected HTTP Host header wpad-fetch-test:%s, got %q", port, sawHost)
	}
}
