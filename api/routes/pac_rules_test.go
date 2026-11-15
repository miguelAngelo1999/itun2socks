package routes

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/pac"
)

func TestPACRulesAndTestEndpoints(t *testing.T) {
	// Serve a test PAC script
	pacServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Write([]byte(`
function FindProxyForURL(url, host) {
    if (dnsDomainIs(host, "corp.local")) {
        return "DIRECT";
    }
    if (shExpMatch(host, "*.internal.net")) {
        return "DIRECT";
    }
    if (isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")) {
        return "DIRECT";
    }
    return "PROXY 10.8.0.1:8082; DIRECT";
}
`))
	}))
	defer pacServer.Close()

	// Set up temp config file
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	configuration.SetConfigFilePath(cfgPath)

	// Add test proxy to configuration
	testProxyID := "test-pac-proxy-1"
	testProxy := map[string]any{
		"id":     testProxyID,
		"name":   "Test PAC Proxy",
		"type":   "http",
		"server": "",
		"port":   0,
		"pacUrl": pacServer.URL,
	}

	cfg := configuration.Config{
		Proxy: []map[string]any{testProxy},
	}
	if err := configuration.Write(cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Set up router
	r := chi.NewRouter()
	r.Get("/{proxyId}/pac-rules", getPACRules)
	r.Post("/{proxyId}/pac-test", testPACUrl)
	r.Get("/{proxyId}/pac-test", testPACUrl)

	// Test 1: GET pac-rules
	req1 := httptest.NewRequest(http.MethodGet, "/"+testProxyID+"/pac-rules", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w1.Code, w1.Body.String())
	}

	var rulesResp struct {
		PacURL    string        `json:"pacUrl"`
		RawScript string        `json:"rawScript"`
		Rules     []PACRuleItem `json:"rules"`
		Upstream  string        `json:"upstream"`
		Error     string        `json:"error"`
	}
	if err := json.Unmarshal(w1.Body.Bytes(), &rulesResp); err != nil {
		t.Fatalf("failed to decode pac-rules json: %v", err)
	}

	if rulesResp.PacURL != pacServer.URL {
		t.Errorf("expected pacUrl %q, got %q", pacServer.URL, rulesResp.PacURL)
	}
	if len(rulesResp.Rules) < 2 {
		t.Errorf("expected at least 2 parsed rules, got %d", len(rulesResp.Rules))
	}
	if rulesResp.RawScript == "" {
		t.Errorf("expected non-empty rawScript")
	}

	// Test 2: POST pac-test with matching DIRECT domain
	body2, _ := json.Marshal(map[string]string{"url": "corp.local"})
	req2 := httptest.NewRequest(http.MethodPost, "/"+testProxyID+"/pac-test", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var testResp2 struct {
		Directive string          `json:"directive"`
		Action    string          `json:"action"`
		Upstream  string          `json:"upstream"`
		Directives []pac.Directive `json:"directives"`
		Error     string          `json:"error"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &testResp2); err != nil {
		t.Fatalf("failed to decode pac-test json: %v", err)
	}

	if testResp2.Action != "DIRECT" {
		t.Errorf("expected action DIRECT for corp.local, got %s", testResp2.Action)
	}

	// Test 3: POST pac-test with non-matching domain -> PROXY
	body3, _ := json.Marshal(map[string]string{"url": "https://www.google.com"})
	req3 := httptest.NewRequest(http.MethodPost, "/"+testProxyID+"/pac-test", bytes.NewReader(body3))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w3.Code, w3.Body.String())
	}

	var testResp3 struct {
		Directive string          `json:"directive"`
		Action    string          `json:"action"`
		Upstream  string          `json:"upstream"`
		Directives []pac.Directive `json:"directives"`
		Error     string          `json:"error"`
	}
	if err := json.Unmarshal(w3.Body.Bytes(), &testResp3); err != nil {
		t.Fatalf("failed to decode pac-test json: %v", err)
	}

	if testResp3.Action != "PROXY" {
		t.Errorf("expected action PROXY for google.com, got %s", testResp3.Action)
	}
	if testResp3.Upstream != "10.8.0.1:8082" {
		t.Errorf("expected upstream 10.8.0.1:8082, got %s", testResp3.Upstream)
	}

	// Test 4: GET pac-test with query param
	req4 := httptest.NewRequest(http.MethodGet, "/"+testProxyID+"/pac-test?url=api.internal.net", nil)
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)

	if w4.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w4.Code, w4.Body.String())
	}

	var testResp4 struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w4.Body.Bytes(), &testResp4); err != nil {
		t.Fatalf("failed to decode pac-test json: %v", err)
	}
	if testResp4.Action != "DIRECT" {
		t.Errorf("expected action DIRECT for api.internal.net, got %s", testResp4.Action)
	}
}
