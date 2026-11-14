package configuration

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProxyFieldTrimming(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "trim_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfgPath := filepath.Join(tmpDir, "config.json")
	SetConfigFilePath(cfgPath)

	rawConfig := `{
		"proxy": [
			{
				"id": "test-proxy-1",
				"name": "  Corporate Proxy  ",
				"server": "   10.10.102.240   ",
				"port": 8080,
				"type": "http",
				"username": "   user123   ",
				"password": "secretpassword"
			}
		],
		"selected": {
			"proxy": "test-proxy-1",
			"rule": ""
		},
		"setting": {
			"mode": "mixed",
			"stack": "system"
		}
	}`

	if err := os.WriteFile(cfgPath, []byte(rawConfig), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := readFile()
	if err != nil {
		t.Fatalf("readFile failed: %v", err)
	}

	if len(cfg.Proxy) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(cfg.Proxy))
	}

	p := cfg.Proxy[0]
	if server, ok := p["server"].(string); !ok || server != "10.10.102.240" {
		t.Errorf("expected trimmed server '10.10.102.240', got '%v'", p["server"])
	}
	if user, ok := p["username"].(string); !ok || user != "user123" {
		t.Errorf("expected trimmed username 'user123', got '%v'", p["username"])
	}
	if name, ok := p["name"].(string); !ok || name != "Corporate Proxy" {
		t.Errorf("expected trimmed name 'Corporate Proxy', got '%v'", p["name"])
	}
}
