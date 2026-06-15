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

func Cache(der []byte) {
	mu.Lock(); defer mu.Unlock()
	cachedCert = der; cachedAt = time.Now()
}

func Cached() ([]byte, time.Time) {
	mu.RLock(); defer mu.RUnlock()
	return cachedCert, cachedAt
}

func PEM() []byte {
	der, _ := Cached()
	if len(der) == 0 { return nil }
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func SaveToHomeDir(homeDir string) error {
	p := PEM()
	if len(p) == 0 { return nil }
	return os.WriteFile(filepath.Join(homeDir, "ssl_inspect_ca.pem"), p, 0o644)
}
