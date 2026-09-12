package routes

// net_probe.go — low-level network probes for the auto-switch controller.
//
// All probes run INSIDE lux_core so they use Go's dialer, which is exempt
// from the TUN redirect. Flutter sockets are NOT exempt — probing from Dart
// while proxy_all is active gives wrong answers.
//
// Two probe kinds:
//   probeProxy  — full HTTP CONNECT through the proxy to captive.apple.com:443.
//                 TCP-open alone is insufficient: Squid can be alive but serving
//                 FATAL-error responses (happened Sep-10 fleet incident).
//                 200 = tunnel OK; 407 = proxy alive (auth required). Both = UP.
//   probeDirect — DNS-free TCP to 1.1.1.1:443, then OS-native captive portal check.

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	probeConnectHost = "captive.apple.com:443"
	probeDirectIP    = "1.1.1.1:443"
	probeTimeout     = 3 * time.Second

	// OS-native captive portal URLs — same ones the OS uses internally.
	// Body must match exactly; any redirect = captive portal.
	portalURLMac  = "http://captive.apple.com/hotspot-detect.html"
	portalURLWin  = "http://www.msftconnecttest.com/connecttest.txt"
	portalBodyMac = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
	portalBodyWin = "Microsoft Connect Test"
)

// ProbeResult holds the outcome of probing one proxy.
type ProbeResult struct {
	ProxyID string
	Alive   bool
	Latency time.Duration
	Err     error
}

// probeProxy tests a proxy via HTTP CONNECT. Returns Alive=true for 200 or 407.
func probeProxy(host string, port int, username, password string) ProbeResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	c, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return ProbeResult{Alive: false, Err: err}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(probeTimeout))

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", probeConnectHost, probeConnectHost)
	if username != "" {
		raw := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req += "Proxy-Authorization: Basic " + raw + "\r\n"
	}
	req += "\r\n"

	if _, err = c.Write([]byte(req)); err != nil {
		return ProbeResult{Alive: false, Err: err}
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return ProbeResult{Alive: false, Err: err}
	}
	resp.Body.Close()
	latency := time.Since(start)

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusProxyAuthRequired {
		return ProbeResult{Alive: true, Latency: latency}
	}
	return ProbeResult{Alive: false, Latency: latency,
		Err: fmt.Errorf("proxy returned %d", resp.StatusCode)}
}

// ProxyCandidate is the input type for probeProxiesParallel.
type ProxyCandidate struct {
	ID       string
	Host     string
	Port     int
	Username string
	Password string
}

// probeProxiesParallel probes all candidates in parallel.
// Results are returned in the same order as input (priority order preserved).
func probeProxiesParallel(candidates []ProxyCandidate) []ProbeResult {
	results := make([]ProbeResult, len(candidates))
	var wg sync.WaitGroup
	for i, c := range candidates {
		wg.Add(1)
		go func(idx int, cand ProxyCandidate) {
			defer wg.Done()
			r := probeProxy(cand.Host, cand.Port, cand.Username, cand.Password)
			r.ProxyID = cand.ID
			results[idx] = r
		}(i, c)
	}
	wg.Wait()
	return results
}

// probeDirect returns true if direct internet works (no proxy needed).
// Stage 1: DNS-free TCP to 1.1.1.1:443.
// Stage 2: content-validated captive portal check using OS-native URL.
func probeDirect() bool {
	c, err := net.DialTimeout("tcp", probeDirectIP, probeTimeout)
	if err != nil {
		return false
	}
	c.Close()

	portalURL := portalURLMac
	expectedBody := portalBodyMac
	if runtime.GOOS == "windows" {
		portalURL = portalURLWin
		expectedBody = portalBodyWin
	}

	client := &http.Client{
		Timeout: probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // redirect = captive portal
		},
	}
	resp, err := client.Get(portalURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	return strings.TrimSpace(string(buf[:n])) == expectedBody
}
