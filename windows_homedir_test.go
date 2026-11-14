package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReconcileWindowsHomeDir(t *testing.T) {
	tempRoot, err := os.MkdirTemp("", "win_homedir_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempRoot)

	// Simulate userConfigDir
	userConfigDir := filepath.Join(tempRoot, "AppData", "Roaming")
	legacyDir := filepath.Join(userConfigDir, "com.github.igoogolx.lux", "1.0")
	canonicalDir := filepath.Join(userConfigDir, "com.github.igoogolx", "lux", "1.0")

	if err := os.MkdirAll(legacyDir, 0755); err != nil {
		t.Fatalf("failed to create legacy dir: %v", err)
	}

	legacyContent := `{"proxy":[{"name":"legacy-proxy","server":"10.0.0.1","port":8080}]}`
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), []byte(legacyContent), 0644); err != nil {
		t.Fatalf("failed to write legacy config: %v", err)
	}

	// Case 1: Pass legacy directory, expect reconciliation to canonical with migration
	resultDir := reconcileWindowsHomeDir(legacyDir, userConfigDir)
	if resultDir != canonicalDir {
		t.Errorf("expected canonical dir %q, got %q", canonicalDir, resultDir)
	}

	migratedData, err := os.ReadFile(filepath.Join(canonicalDir, "config.json"))
	if err != nil {
		t.Fatalf("failed to read migrated config: %v", err)
	}
	if string(migratedData) != legacyContent {
		t.Errorf("expected migrated content %s, got %s", legacyContent, string(migratedData))
	}

	// Case 2: Update legacy config with newer timestamp, expect re-migration to canonical
	time.Sleep(10 * time.Millisecond)
	updatedLegacy := `{"proxy":[{"name":"updated-proxy","server":"10.0.0.2","port":8080}]}`
	if err := os.WriteFile(filepath.Join(legacyDir, "config.json"), []byte(updatedLegacy), 0644); err != nil {
		t.Fatalf("failed to update legacy config: %v", err)
	}

	resultDir2 := reconcileWindowsHomeDir(canonicalDir, userConfigDir)
	if resultDir2 != canonicalDir {
		t.Errorf("expected canonical dir %q, got %q", canonicalDir, resultDir2)
	}

	migratedData2, err := os.ReadFile(filepath.Join(canonicalDir, "config.json"))
	if err != nil {
		t.Fatalf("failed to read re-migrated config: %v", err)
	}
	if string(migratedData2) != updatedLegacy {
		t.Errorf("expected updated content %s, got %s", updatedLegacy, string(migratedData2))
	}
}
