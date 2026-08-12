package blackbox

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/pkg/log"
)

var (
	healthMu   sync.Mutex
	healthStop chan struct{}
	wasHealthy = true
)

// StartHealthCheck probes connectivity every interval. When the probe fails
// twice in a row, it records a connectivity-lost event. When it recovers, it
// records connectivity-restored. The probe bypasses the TUN (dials DIRECT) so
// it tests the actual upstream path.
func StartHealthCheck(interval time.Duration, proxyAddr string) {
	healthMu.Lock()
	defer healthMu.Unlock()
	if healthStop != nil {
		close(healthStop)
	}
	healthStop = make(chan struct{})
	stop := healthStop
	wasHealthy = true

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		consecutiveFails := 0

		for {
			select {
			case <-ticker.C:
				ok := probeConnectivity(proxyAddr)
				if ok {
					if consecutiveFails >= 2 {
						ConnectivityRestored()
						log.Infoln("[healthcheck] connectivity restored")
					}
					consecutiveFails = 0
					wasHealthy = true
				} else {
					consecutiveFails++
					if consecutiveFails == 2 && wasHealthy {
						ConnectivityLost("health probe failed 2x consecutively via " + proxyAddr)
						wasHealthy = false
					}
				}
			case <-stop:
				return
			}
		}
	}()
}

// StopHealthCheck stops the background probe.
func StopHealthCheck() {
	healthMu.Lock()
	defer healthMu.Unlock()
	if healthStop != nil {
		close(healthStop)
		healthStop = nil
	}
}

// probeConnectivity tries to reach a well-known host through the proxy.
func probeConnectivity(proxyAddr string) bool {
	if proxyAddr == "" {
		// No proxy — try direct TCP to a DNS server
		conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 5*time.Second)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}

	// Try CONNECT through the proxy to a known host
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send a minimal HTTP request to check auth is still valid
	req := "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n"
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	// 200 = tunnel established, 407 = auth required (credential expired)
	response := string(buf[:n])
	if len(response) >= 12 {
		code := response[9:12]
		if code == "200" {
			return true
		}
		if code == "407" {
			// Auth failed — proxy is reachable but creds are bad
			Record("proxy-auth-probe-failed", "health probe got 407 from "+proxyAddr, nil)
			return false
		}
	}
	return false
}

// IsHealthy returns current connectivity state.
func IsHealthy() bool {
	return wasHealthy
}

// unused but satisfies the import
var _ = http.StatusOK
