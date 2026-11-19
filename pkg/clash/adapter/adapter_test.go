package adapter

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
)

func startConnectProxy(t *testing.T) *httptest.Server {
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

func TestURLTest_PerDialInterfaceOption(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	proxySrv := startConnectProxy(t)
	defer proxySrv.Close()

	host, portStr, err := net.SplitHostPort(proxySrv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	p, err := ParseProxy(map[string]any{
		"type":   "http",
		"name":   "test-http",
		"server": host,
		"port":   port,
	})
	if err != nil {
		t.Fatalf("ParseProxy failed: %v", err)
	}

	prevIface := dialer.DefaultInterface.Load()
	dialer.DefaultInterface.Store("nonexistent-iface0")
	t.Cleanup(func() { dialer.DefaultInterface.Store(prevIface) })

	// Without WithInterface(""), DialContext uses DefaultInterface and fails.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel1()
	if _, _, err := p.URLTest(ctx1, target.URL); err == nil || !strings.Contains(err.Error(), "interface not found") {
		t.Fatalf("expected interface not found error without WithInterface, got: %v", err)
	}

	// With dialer.WithInterface(""), concurrent URLTest calls succeed and never mutate DefaultInterface.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _, err := p.URLTest(ctx, target.URL, dialer.WithInterface(""))
			if err != nil {
				errs <- err
			}
			if got := dialer.DefaultInterface.Load(); got != "nonexistent-iface0" {
				errs <- net.InvalidAddrError("DefaultInterface mutated to " + got)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent URLTest failed: %v", err)
	}
	if got := dialer.DefaultInterface.Load(); got != "nonexistent-iface0" {
		t.Fatalf("DefaultInterface changed: got %q, want %q", got, "nonexistent-iface0")
	}
}
