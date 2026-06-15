package ssl_inspect

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	mu         sync.RWMutex
	cachedCert []byte
	cachedAt   time.Time
)

// Cache stores the detected intercept CA cert (DER encoded).
func Cache(der []byte) {
	mu.Lock()
	defer mu.Unlock()
	cachedCert = der
	cachedAt = time.Now()
}

// Cached returns the stored DER cert and when it was cached.
func Cached() ([]byte, time.Time) {
	mu.RLock()
	defer mu.RUnlock()
	return cachedCert, cachedAt
}

// PEM returns the cached cert as PEM-encoded bytes, or nil if none cached.
func PEM() []byte {
	der, _ := Cached()
	if len(der) == 0 {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// SaveToHomeDir writes the cert PEM to homeDir/ssl_inspect_ca.pem.
func SaveToHomeDir(homeDir string) error {
	p := PEM()
	if len(p) == 0 {
		return nil
	}
	return os.WriteFile(filepath.Join(homeDir, "ssl_inspect_ca.pem"), p, 0o644)
}
