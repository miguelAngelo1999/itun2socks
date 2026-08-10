package pac

import (
	"testing"
)

// The routing fallback reads a PAC result and only honours DIRECT, treating
// everything else as "use the configured proxy". That parsing is the hinge of the
// whole hierarchy, so it is worth pinning: read DIRECT where the script does not
// mean it and internal traffic leaks to the proxy; miss a DIRECT and internal
// hosts break.
//
// Mirrors the check in pkg/clash/tunnel.match().
func saysDirect(result string) bool {
	return IsDirectResult(result)
}

func TestDirectResultParsing(t *testing.T) {
	cases := []struct {
		name   string
		result string
		direct bool
	}{
		{"plain DIRECT", "DIRECT", true},
		{"lowercase", "direct", true},
		{"padded", "  DIRECT  ", true},
		{"trailing semicolon", "DIRECT;", true},
		{"DIRECT preferred first", "DIRECT; PROXY 10.8.0.1:8082", true},

		{"proxy only", "PROXY 10.8.0.1:8082", false},
		{"lowercase proxy", "proxy 10.8.0.1:8082", false},
		{"socks", "SOCKS5 127.0.0.1:1080", false},
		// A proxy listed first decides; falling back to DIRECT here would send
		// traffic the script wanted proxied straight out.
		{"proxy then direct", "PROXY 10.8.0.1:8082; DIRECT", false},
		// Nothing usable. The caller must not read this as DIRECT, or a PAC that
		// failed to evaluate would silently unproxy everything.
		{"empty", "", false},
		{"whitespace", "   ", false},
		{"garbage", "not a pac result", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := saysDirect(c.result); got != c.direct {
				t.Fatalf("isDirectResult(%q) = %v, want %v", c.result, got, c.direct)
			}
		})
	}
}
