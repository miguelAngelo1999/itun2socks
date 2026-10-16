package adapter

import (
	"testing"

	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
)

// A proxy with a PAC URL and no server builds the PAC-only dynamic outbound.
func TestParseProxy_PacOnly(t *testing.T) {
	p, err := ParseProxy(map[string]any{
		"id":       "pac-1",
		"type":     "http",
		"name":     "corp-pac",
		"pacUrl":   "http://proxy.corp/proxy.pac",
		"username": "u",
		"password": "p",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("nil proxy")
	}
	if p.Type() != C.Http {
		t.Fatalf("want Http adapter type, got %v", p.Type())
	}
}

// A normal server-based proxy is unaffected by the PAC-only branch.
func TestParseProxy_ServerBasedUnchanged(t *testing.T) {
	p, err := ParseProxy(map[string]any{
		"id":     "srv-1",
		"type":   "http",
		"name":   "plain",
		"server": "10.0.0.1",
		"port":   8080,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil || p.Type() != C.Http {
		t.Fatalf("want Http proxy, got %v err=%v", p, err)
	}
}

// A server-based proxy that ALSO carries a PAC (PAC-gates-server) must take the
// normal path, not the PAC-only branch.
func TestParseProxy_ServerPlusPacTakesNormalPath(t *testing.T) {
	p, err := ParseProxy(map[string]any{
		"id":     "srv-pac",
		"type":   "socks5",
		"name":   "gated",
		"server": "10.0.0.2",
		"port":   1080,
		"pacUrl": "http://proxy.corp/proxy.pac",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Type() != C.Socks5 {
		t.Fatalf("want Socks5 (normal path), got %v", p.Type())
	}
}
