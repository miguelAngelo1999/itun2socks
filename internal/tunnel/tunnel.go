package tunnel

import (
	"runtime"
	"strings"
)

// IsProxyDenied reports whether an error represents an upstream proxy rejecting/denying
// the connection (e.g. HTTP 403 Forbidden, 407 Auth Required, 405, 502/503/504, SOCKS5 REP error).
func IsProxyDenied(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "denied") ||
		strings.Contains(s, "403") ||
		strings.Contains(s, "407") ||
		strings.Contains(s, "not allowed") ||
		strings.Contains(s, "proxy rejected") ||
		strings.Contains(s, "proxy gateway error") ||
		strings.Contains(s, "socks5 rep") ||
		strings.Contains(s, "auth rejected")
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
