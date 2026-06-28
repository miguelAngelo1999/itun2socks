package executor

import (
	"path/filepath"

	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/mitm"
	"github.com/igoogolx/itun2socks/internal/tunnel"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// InitMitm initialises the MITM CA and interceptor from persisted config.
// Called once at startup. Idempotent — safe to call multiple times.
func InitMitm() {
	configFilePath, err := configuration.GetConfigFilePath()
	if err != nil || configFilePath == "" {
		log.Warnln("[MITM] could not get config path, skipping init: %v", err)
		return
	}
	configDir := filepath.Dir(configFilePath)

	ca, err := mitm.GetOrInitCA(configDir)
	if err != nil {
		log.Warnln("[MITM] CA init failed: %v", err)
		return
	}
	mitm.SetGlobalCA(ca)

	// Load persisted inspection settings
	cfg, _ := configuration.GetSslInspectionSettings()
	entries, _ := configuration.GetInspectionList()

	list := mitm.NewInspectionList()
	mitmEntries := make([]mitm.InspectionListEntry, len(entries))
	for i, e := range entries {
		mitmEntries[i] = mitm.InspectionListEntry{Pattern: e.Pattern, Enabled: e.Enabled}
	}
	list.LoadFrom(mitmEntries)

	interceptor := mitm.NewMitmInterceptor(ca, list)
	interceptor.SetEnabled(cfg.Enabled)

	// Register with the singleton (used by API routes)
	mitm.SetGlobalInterceptor(interceptor)

	// Register with the TCP tunnel handler (triggers actual interception)
	tunnel.SetMitmInterceptor(interceptor)

	log.Infoln("[MITM] initialized, enabled=%v, domains=%d", cfg.Enabled, len(entries))
}
