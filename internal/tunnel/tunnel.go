package tunnel

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/clash/transport/socks5"
)

// ClassifyProxyError inspects a dial/handshake error and returns a short
// diagnostic tag (e.g. "HTTP 403", "HTTP 407", "SOCKS5 DENY", "HTTP 502")
// along with whether the error represents an upstream proxy rejection/denial.
func ClassifyProxyError(err error) (tag string, denied bool) {
	if err == nil {
		return "", false
	}
	if errors.Is(err, socks5.ErrAuth) {
		return "SOCKS5 AUTH", true
	}
	if errors.Is(err, socks5.ErrConnectionNotAllowed) {
		return "SOCKS5 DENY", true
	}

	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "403"):
		return "HTTP 403", true
	case strings.Contains(s, "407"):
		return "HTTP 407", true
	case strings.Contains(s, "405"):
		return "HTTP 405", true
	case strings.Contains(s, "auth rejected"):
		return "AUTH LATCHED", true
	case strings.Contains(s, "socks need auth") || strings.Contains(s, "rejected username/password") || strings.Contains(s, "auth failed"):
		return "SOCKS5 AUTH", true
	case strings.Contains(s, "socks5 rep 2") || (strings.Contains(s, "socks5") && strings.Contains(s, "not allowed")):
		return "SOCKS5 DENY", true
	case strings.Contains(s, "socks5 rep"):
		return "SOCKS5 ERR", true
	case strings.Contains(s, "502"):
		if strings.Contains(s, "proxy") || strings.Contains(s, "gateway") {
			return "HTTP 502", true
		}
	case strings.Contains(s, "503"):
		if strings.Contains(s, "proxy") || strings.Contains(s, "gateway") {
			return "HTTP 503", true
		}
	case strings.Contains(s, "504"):
		if strings.Contains(s, "proxy") || strings.Contains(s, "gateway") {
			return "HTTP 504", true
		}
	}

	if strings.Contains(s, "denied") ||
		strings.Contains(s, "not allowed") ||
		strings.Contains(s, "proxy rejected") ||
		strings.Contains(s, "proxy gateway error") {
		return "PROXY DENY", true
	}
	return "", false
}

// IsProxyDenied reports whether an error represents an upstream proxy rejecting/denying
// the connection (e.g. HTTP 403 Forbidden, 407 Auth Required, 405, 502/503/504, SOCKS5 REP/auth error).
func IsProxyDenied(err error) bool {
	_, denied := ClassifyProxyError(err)
	return denied
}

// isEarlyUpstreamReset detects when an upstream proxy accepts CONNECT (200 OK)
// and then immediately drops/resets the tunnel after the client sends its first
// bytes (typically a TLS ClientHello) with zero response bytes (or only a tiny
// <=7-byte TLS fatal alert) — the exact signature of Squid `ssl_bump terminate`
// or an upstream SNI/TLS firewall drop.
func isEarlyUpstreamReset(policy constants.Policy, uploadBytes, downloadBytes int64, elapsed time.Duration, relayErr error) bool {
	if policy == constants.PolicyDirect || policy == constants.PolicyReject {
		return false
	}
	if elapsed > 5*time.Second {
		return false
	}
	if uploadBytes <= 0 || downloadBytes > 7 {
		return false
	}
	if relayErr != nil {
		if errors.Is(relayErr, context.Canceled) {
			return false
		}
		s := strings.ToLower(relayErr.Error())
		// Client itself closed/aborted the local socket (e.g. browser cancelled tab).
		if strings.Contains(s, "127.0.0.1") && (strings.Contains(s, "broken pipe") || strings.Contains(s, "use of closed")) {
			return false
		}
		if strings.Contains(s, "canceled") || strings.Contains(s, "cancelled") {
			return false
		}
	}
	return true
}

func process() {
	numUDPWorkers := max(runtime.NumCPU(), 4)
	for i := 0; i < numUDPWorkers; i++ {
		go processUDP()
	}
	go processTCP()
}

func init() {
	go process()
}
