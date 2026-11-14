package adapter

import (
	"testing"
)

func TestParseProxyTrimming(t *testing.T) {
	mapping := map[string]any{
		"type":     "http",
		"name":     "   Test HTTP Proxy   ",
		"server":   "   192.168.1.100   ",
		"port":     8080,
		"username": "   admin_user   ",
		"password": "secret",
	}

	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy failed: %v", err)
	}

	if proxy.Name() != "Test HTTP Proxy" {
		t.Errorf("expected trimmed proxy name 'Test HTTP Proxy', got '%v'", proxy.Name())
	}
	if proxy.Addr() != "192.168.1.100:8080" {
		t.Errorf("expected trimmed proxy addr '192.168.1.100:8080', got '%v'", proxy.Addr())
	}
}
