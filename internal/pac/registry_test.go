package pac

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestRegistry_UpdateRetriesWhenCompiledNil(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`function FindProxyForURL(url, host) { return "PROXY 10.8.0.1:8082"; }`))
	}))
	defer srv.Close()

	reg := NewRegistry()
	proxies := []map[string]any{
		{
			"id":     "p1",
			"server": "",
			"pacUrl": srv.URL,
		},
	}

	// First attempt fails -> compiled is nil
	reg.Update(proxies, "")
	if _, hasPAC, _ := reg.EvalDirective("p1", "https://example.com/", "example.com"); hasPAC {
		t.Fatalf("expected hasPAC=false after failed fetch")
	}

	// Second Update with same URL MUST retry because compiled == nil
	reg.Update(proxies, "")
	dir, hasPAC, timedOut := reg.EvalDirective("p1", "https://example.com/", "example.com")
	if !hasPAC || timedOut || dir != "PROXY 10.8.0.1:8082" {
		t.Fatalf("expected compiled PAC on retry, got dir=%q hasPAC=%v timedOut=%v", dir, hasPAC, timedOut)
	}
}

func TestRegistry_RetryCompile(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`function FindProxyForURL(url, host) { return "PROXY 10.8.0.1:8082"; }`))
	}))
	defer srv.Close()

	reg := NewRegistry()
	reg.Update([]map[string]any{{"id": "p1", "server": "", "pacUrl": srv.URL}}, "")

	if ok := reg.RetryCompile("p1"); !ok {
		t.Fatalf("expected RetryCompile to succeed when server recovers")
	}
	dir, hasPAC, _ := reg.EvalDirective("p1", "https://example.com/", "example.com")
	if !hasPAC || dir != "PROXY 10.8.0.1:8082" {
		t.Fatalf("unexpected directive after RetryCompile: %q (hasPAC=%v)", dir, hasPAC)
	}
}
