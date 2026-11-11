package pac

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestCompiledPAC_BasicAndHelpers(t *testing.T) {
	js := `
function isInternal(h) {
    return dnsDomainIs(h, ".internal.corp") || localHostOrDomainIs(h, "intranet");
}

function FindProxyForURL(url, host) {
    alert("evaluating " + host);
    if (isPlainHostName(host) || (host == "localhost" || host == "127.0.0.1")) {
        return "DIRECT";
    }
    if (dnsDomainLevels(host) == 0) {
        return "DIRECT";
    }
    if (isInternal(host)) {
        return "DIRECT";
    }
    if (shExpMatch(host, "*.corp.example.com")) {
        return "PROXY proxy1.corp.example.com:8080; DIRECT";
    }
    if (isInNet(host, "10.0.0.0", "255.0.0.0")) {
        return "PROXY 10.0.0.1:8080";
    }
    if (isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")) {
        return "SOCKS5 192.168.1.1:1080";
    }
    var myIP = myIpAddress();
    var myIPEx = myIpAddressEx();
    if (myIP == "127.0.0.1" && myIPEx == "127.0.0.1") {
        // loopback test
    }
    if (convert_addr(host) == "special.test") {
        return "HTTP special-proxy:3128";
    }
    return "PROXY fallback.example.com:8080; SOCKS5 fallback.example.com:1080; DIRECT";
}
`
	pac, err := Compile(js)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}

	tests := []struct {
		name     string
		url      string
		host     string
		expected string
	}{
		{"plain hostname", "http://intranet/", "intranet", "DIRECT"},
		{"localhost", "http://localhost:8080/", "localhost", "DIRECT"},
		{"127.0.0.1", "http://127.0.0.1/", "127.0.0.1", "DIRECT"},
		{"internal domain", "http://app.internal.corp/", "app.internal.corp", "DIRECT"},
		{"shExpMatch corp", "http://mail.corp.example.com/", "mail.corp.example.com", "PROXY proxy1.corp.example.com:8080; DIRECT"},
		{"isInNet 10.x IP", "http://10.1.2.3:80/", "10.1.2.3", "PROXY 10.0.0.1:8080"},
		{"convert_addr", "http://special.test/", "special.test", "HTTP special-proxy:3128"},
		{"fallback", "https://google.com/", "google.com", "PROXY fallback.example.com:8080; SOCKS5 fallback.example.com:1080; DIRECT"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pac.Eval(tc.url, tc.host)
			if got != tc.expected {
				t.Errorf("Eval(%q, %q) = %q; want %q", tc.url, tc.host, got, tc.expected)
			}
		})
	}
}

func TestCompiledPAC_TimeAndDateHelpers(t *testing.T) {
	js := `
function FindProxyForURL(url, host) {
    if (weekdayRange("MON", "SUN")) {
        // Always true since MON to SUN covers all 7 days
    } else {
        return "FAIL_WEEKDAY";
    }

    if (timeRange(0, 23)) {
        // Always true since 0 to 23 covers all hours
    } else {
        return "FAIL_TIME";
    }

    if (dateRange(1, 31)) {
        // Always true since days are 1-31
    } else {
        return "FAIL_DATE";
    }

    return "DIRECT";
}
`
	pac, err := Compile(js)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}

	got := pac.Eval("http://example.com/", "example.com")
	if got != "DIRECT" {
		t.Errorf("Eval result = %q; want DIRECT", got)
	}
}

func TestCompiledPAC_Timeout(t *testing.T) {
	js := `
function FindProxyForURL(url, host) {
    while (true) {}
    return "DIRECT";
}
`
	pac, err := Compile(js)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}

	start := time.Now()
	res, timedOut := pac.EvalRaw("http://example.com/", "example.com")
	elapsed := time.Since(start)

	if !timedOut {
		t.Errorf("expected timedOut = true, got false (res = %q)", res)
	}
	if elapsed < 1400*time.Millisecond || elapsed > 3500*time.Millisecond {
		t.Errorf("expected timeout around 1500ms, elapsed: %v", elapsed)
	}

	// Verify Eval returns DIRECT on timeout
	resEval := pac.Eval("http://example.com/", "example.com")
	if resEval != "DIRECT" {
		t.Errorf("Eval expected DIRECT on timeout, got %q", resEval)
	}
}

func TestExtractUpstreams(t *testing.T) {
	js := `
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.a.com")) return "PROXY proxy-a.corp:8080";
    if (shExpMatch(host, "*.b.com")) return "HTTP proxy-b.corp:3128; SOCKS5 socks-b.corp:1080";
    if (shExpMatch(host, "*.c.com")) return "HTTPS proxy-c.corp:8443; SOCKS socks-c.corp:1080; DIRECT";
    return "DIRECT";
}
`
	pac, err := Compile(js)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}

	dirs := pac.ExtractUpstreams()
	if len(dirs) != 5 {
		t.Fatalf("expected 5 upstreams, got %d: %+v", len(dirs), dirs)
	}

	hosts := pac.ExtractUpstreamHosts()
	expectedHosts := []string{"proxy-a.corp", "proxy-b.corp", "socks-b.corp", "proxy-c.corp", "socks-c.corp"}
	if len(hosts) != len(expectedHosts) {
		t.Fatalf("expected %d hosts, got %d: %+v", len(expectedHosts), len(hosts), hosts)
	}
	for i, h := range expectedHosts {
		if hosts[i] != h {
			t.Errorf("host %d: got %s, want %s", i, hosts[i], h)
		}
	}
}

func TestEnterpriseWPADPattern(t *testing.T) {
	// Real-world enterprise wpad.dat pattern
	js := `
// Enterprise Proxy Auto-Configuration Script
function FindProxyForURL(url, host) {
    // Normalize host
    host = host.toLowerCase();

    // 1. Direct for plain hostnames, localhost, and RFC1918 addresses
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(host, "127.0.0.0", "255.0.0.0") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0")) {
        return "DIRECT";
    }

    // 2. Direct for corporate internal domains
    if (dnsDomainIs(host, ".internal.mycorp.com") ||
        dnsDomainIs(host, ".corp.mycorp.com") ||
        shExpMatch(host, "(*.mycorp.net|*.dev.mycorp.net)")) {
        return "DIRECT";
    }

    // 3. DMZ proxies for external partners
    if (dnsDomainIs(host, ".partner-portal.com")) {
        return "PROXY dmz-proxy.mycorp.com:8080; DIRECT";
    }

    // 4. Default outbound proxies with failover
    return "PROXY proxy-cluster.mycorp.com:8080; PROXY backup-proxy.mycorp.com:8080; DIRECT";
}
`
	pac, err := Compile(js)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}

	tests := []struct {
		url      string
		host     string
		expected string
	}{
		{"http://payroll/", "payroll", "DIRECT"},
		{"http://test.local/", "test.local", "DIRECT"},
		{"http://10.200.1.5/", "10.200.1.5", "DIRECT"},
		{"http://172.20.10.1/", "172.20.10.1", "DIRECT"},
		{"http://192.168.1.100/", "192.168.1.100", "DIRECT"},
		{"http://wiki.internal.mycorp.com/", "wiki.internal.mycorp.com", "DIRECT"},
		{"http://api.partner-portal.com/", "api.partner-portal.com", "PROXY dmz-proxy.mycorp.com:8080; DIRECT"},
		{"https://github.com/", "github.com", "PROXY proxy-cluster.mycorp.com:8080; PROXY backup-proxy.mycorp.com:8080; DIRECT"},
	}

	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			got := pac.Eval(tc.url, tc.host)
			if got != tc.expected {
				t.Errorf("Eval(%q, %q) = %q; want %q", tc.url, tc.host, got, tc.expected)
			}
		})
	}

	// Verify upstream extraction from wpad script
	upstreams := pac.ExtractUpstreams()
	if len(upstreams) != 3 {
		t.Errorf("expected 3 upstreams, got %d: %+v", len(upstreams), upstreams)
	}
	hosts := pac.ExtractUpstreamHosts()
	if len(hosts) != 3 || hosts[0] != "dmz-proxy.mycorp.com" || hosts[1] != "proxy-cluster.mycorp.com" || hosts[2] != "backup-proxy.mycorp.com" {
		t.Errorf("unexpected extracted upstream hosts: %+v", hosts)
	}
}

func TestLocalLookupAndFakeIP(t *testing.T) {
	// Set custom local lookup that returns Fake-IP and a real IP
	SetLocalLookup(func(ctx context.Context, host string) ([]string, error) {
		if host == "fake.test" {
			return []string{"198.18.0.1"}, nil
		}
		if host == "real.test" {
			return []string{"198.18.0.2", "192.168.1.50"}, nil
		}
		return nil, nil
	})
	defer SetLocalLookup(nil)

	// Fake-IP only should be ignored and fallback/return empty
	if res := GoLookup("fake.test"); res != "" {
		t.Errorf("GoLookup(fake.test) = %q; want empty", res)
	}

	// Real IP mixed with Fake-IP should pick the real non-fake IP
	if res := GoLookup("real.test"); res != "192.168.1.50" {
		t.Errorf("GoLookup(real.test) = %q; want 192.168.1.50", res)
	}
}

func TestLiveWPAD(t *testing.T) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://wpad/wpad.dat")
	if err != nil {
		t.Skipf("http://wpad/wpad.dat not reachable: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read wpad: %v", err)
	}
	t.Logf("Fetched live WPAD: %d bytes", len(body))

	compiled, err := Compile(string(body))
	if err != nil {
		t.Fatalf("compile live WPAD: %v", err)
	}

	upstreams := compiled.ExtractUpstreams()
	t.Logf("Extracted %d upstreams: %+v", len(upstreams), upstreams)

	samples := []struct {
		url  string
		host string
	}{
		{"https://www.google.com/", "www.google.com"},
		{"https://github.com/", "github.com"},
		{"http://localhost/", "localhost"},
		{"http://intranet/", "intranet"},
		{"http://10.0.0.1/", "10.0.0.1"},
		{"http://192.168.1.1/", "192.168.1.1"},
	}

	for _, s := range samples {
		res := compiled.Eval(s.url, s.host)
		dirs := ParseDirectives(res)
		t.Logf("Eval(%s) => %q (directives: %+v)", s.host, res, dirs)
	}
}
