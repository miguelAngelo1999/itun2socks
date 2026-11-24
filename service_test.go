package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateStartCoreRequest(t *testing.T) {
	valid := startCoreRequest{
		HomeDir: `C:\Users\daniel.silva\AppData\Roaming\com.github.igoogolx\lux\1.0`,
		Port:    8000,
		Secret:  "5eec8115-2b2d-49cd-ac34-9b3119fe8d4e",
		UserSID: "S-1-5-21-3623811015-3361044348-30300820-1013",
	}
	if err := validateStartCoreRequest(valid, 41957); err != nil {
		t.Fatalf("expected valid request, got: %v", err)
	}

	// Legacy dotted path is also allowed
	legacy := valid
	legacy.HomeDir = `C:\Users\João Silva\AppData\Roaming\com.github.igoogolx.lux\1.0`
	if err := validateStartCoreRequest(legacy, 41957); err != nil {
		t.Fatalf("expected legacy path valid, got: %v", err)
	}

	// Empty userSid is allowed
	noSid := valid
	noSid.UserSID = ""
	if err := validateStartCoreRequest(noSid, 41957); err != nil {
		t.Fatalf("expected empty userSid valid, got: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*startCoreRequest)
	}{
		{"port too low", func(r *startCoreRequest) { r.Port = 80 }},
		{"port equals controlPort", func(r *startCoreRequest) { r.Port = 41957 }},
		{"secret too short", func(r *startCoreRequest) { r.Secret = "short" }},
		{"secret with spaces", func(r *startCoreRequest) { r.Secret = "bad secret token" }},
		{"invalid userSid", func(r *startCoreRequest) { r.UserSID = "evil;whoami" }},
		{"arbitrary homeDir", func(r *startCoreRequest) { r.HomeDir = `C:\Windows\System32` }},
		{"path traversal homeDir", func(r *startCoreRequest) { r.HomeDir = `C:\Users\a\..\..\com.github.igoogolx\lux\1.0` }},
		{"relative homeDir", func(r *startCoreRequest) { r.HomeDir = `com.github.igoogolx\lux\1.0` }},
		{"shell metachar homeDir", func(r *startCoreRequest) { r.HomeDir = `C:\Users\a&calc\com.github.igoogolx\lux\1.0` }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := valid
			tc.mutate(&req)
			if err := validateStartCoreRequest(req, 41957); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestCoreServiceSupervisorAuthAndHealth(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "lux_core.exe")
	if err := os.WriteFile(fakeBin, []byte("fake-core-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	sup, err := newCoreServiceSupervisor(fakeBin, "super-secret-control-token", 41957, nil)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(sup.handler())
	defer srv.Close()

	// 1. /health works without auth and returns worker SHA-256
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /health, got %d", resp.StatusCode)
	}
	var health serviceHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if !health.OK || len(health.CoreSHA256) != 64 || health.Running {
		t.Fatalf("unexpected health response: %+v", health)
	}

	// 2. /start-core rejects missing or wrong token
	reqBody := bytes.NewBufferString(`{"homeDir":"C:\\Users\\a\\AppData\\Roaming\\com.github.igoogolx\\lux\\1.0","port":8000,"secret":"abcdefgh1234"}`)
	resp2, err := http.Post(srv.URL+"/start-core", "application/json", reqBody)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp2.StatusCode)
	}

	// 3. /start-core rejects invalid homeDir even with valid token
	badReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/start-core",
		bytes.NewBufferString(`{"homeDir":"C:\\Windows\\System32","port":8000,"secret":"abcdefgh1234"}`))
	badReq.Header.Set("Authorization", "Bearer super-secret-control-token")
	resp3, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid homeDir, got %d", resp3.StatusCode)
	}

	// 4. /stop-core succeeds idempotently with valid token
	stopReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/stop-core", nil)
	stopReq.Header.Set("Authorization", "Bearer super-secret-control-token")
	resp4, err := http.DefaultClient.Do(stopReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /stop-core, got %d", resp4.StatusCode)
	}
}
