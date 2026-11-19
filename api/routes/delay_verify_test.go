package routes

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/pkg/clash/adapter"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
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

func startTunnelProxy(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		dest, err := net.DialTimeout("tcp", r.Host, 2*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			dest.Close()
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hj.Hijack()
		if err != nil {
			dest.Close()
			return
		}
		_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() {
			defer dest.Close()
			defer clientConn.Close()
			_, _ = io.Copy(dest, clientConn)
		}()
		go func() {
			defer dest.Close()
			defer clientConn.Close()
			_, _ = io.Copy(clientConn, dest)
		}()
	}))
}

func TestGetProxyDelayTimeoutAndConcurrentNoGlobalMutation(t *testing.T) {
	if defaultDelayTimeout != 10*time.Second {
		t.Fatalf("expected defaultDelayTimeout == 10s, got %v", defaultDelayTimeout)
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	proxySrv := startTunnelProxy(t)
	defer proxySrv.Close()

	host, portStr, err := net.SplitHostPort(proxySrv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	tmpDir := t.TempDir()
	configuration.SetConfigFilePath(filepath.Join(tmpDir, "config.json"))
	proxyID := "delay-concurrency-proxy"
	cfg := configuration.Config{
		Proxy: []map[string]any{
			{
				"id":     proxyID,
				"name":   "Delay Test Proxy",
				"type":   "http",
				"server": host,
				"port":   port,
			},
		},
	}
	if err := configuration.Write(cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevTestURL := defaultDelayTestUrl
	defaultDelayTestUrl = target.URL
	t.Cleanup(func() { defaultDelayTestUrl = prevTestURL })

	prevIface := dialer.DefaultInterface.Load()
	dialer.DefaultInterface.Store("nonexistent-iface0")
	t.Cleanup(func() { dialer.DefaultInterface.Store(prevIface) })

	r := chi.NewRouter()
	r.Get("/delay/{proxyId}", getProxyDelay)

	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/delay/"+proxyID, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				errs <- "unexpected status " + strconv.Itoa(w.Code) + ": " + w.Body.String()
				return
			}
			var body struct {
				Delay int    `json:"delay"`
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				errs <- "invalid json: " + err.Error()
				return
			}
			if body.Delay < 0 || body.Error != "" {
				errs <- "delay test failed: " + w.Body.String()
				return
			}
			if got := dialer.DefaultInterface.Load(); got != "nonexistent-iface0" {
				errs <- "DefaultInterface mutated to " + got
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
	if got := dialer.DefaultInterface.Load(); got != "nonexistent-iface0" {
		t.Fatalf("DefaultInterface changed: got %q, want %q", got, "nonexistent-iface0")
	}
}
