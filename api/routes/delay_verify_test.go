package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/igoogolx/itun2socks/pkg/clash/adapter"
)

// Mock upstream HTTP proxy that requires Basic Auth
func startMockProxy(authHeader string) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			if authHeader != "" && r.Header.Get("Proxy-Authorization") != authHeader {
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			// Success CONNECT
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(handler)
}

func TestDelayErrorAndLeadingSpaces(t *testing.T) {
	// Start mock proxy requiring auth
	// Basic user:pass => dXNlcjpwYXNz
	expectedAuth := "Basic dXNlcjpwYXNz"
	mockProxy := startMockProxy(expectedAuth)
	defer mockProxy.Close()

	proxyURL := mockProxy.Listener.Addr().String()
	host, portStr, _ := netSplit(proxyURL)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	// Case 1: Bad creds -> expect 407 error
	badCredsMapping := map[string]any{
		"type":     "http",
		"name":     "Bad Creds Proxy",
		"server":   host,
		"port":     port,
		"username": "wronguser",
		"password": "wrongpassword",
	}

	badProxy, err := adapter.ParseProxy(badCredsMapping)
	if err != nil {
		t.Fatalf("ParseProxy failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err = badProxy.URLTest(ctx, "http://example.com")
	if err == nil {
		t.Errorf("expected 407 error for bad creds, got nil")
	} else if err.Error() != "upstream proxy authentication required (HTTP 407)" {
		t.Errorf("expected HTTP 407 message, got %q", err.Error())
	}

	// Case 2: Leading spaces on server IP -> should be trimmed and connect successfully
	spacedMapping := map[string]any{
		"type":     "http",
		"name":     "  Spaced Proxy  ",
		"server":   "     " + host + "   ",
		"port":     port,
		"username": "   user   ",
		"password": "pass",
	}

	spacedProxy, err := adapter.ParseProxy(spacedMapping)
	if err != nil {
		t.Fatalf("ParseProxy with spaces failed: %v", err)
	}

	if spacedProxy.Addr() != proxyURL {
		t.Errorf("expected trimmed addr %q, got %q", proxyURL, spacedProxy.Addr())
	}

	// Case 3: Unreachable IP -> expect dial / network failure
	unreachableMapping := map[string]any{
		"type":     "http",
		"name":     "Unreachable Proxy",
		"server":   "192.0.2.1", // TEST-NET-1 (unroutable/unreachable)
		"port":     8080,
		"username": "user",
		"password": "pass",
	}

	unreachProxy, err := adapter.ParseProxy(unreachableMapping)
	if err != nil {
		t.Fatalf("ParseProxy failed: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()

	_, _, err = unreachProxy.URLTest(ctx2, "http://example.com")
	if err == nil {
		t.Errorf("expected error for unreachable IP, got nil")
	}
}

func netSplit(addr string) (string, string, error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return addr, "", nil
}
