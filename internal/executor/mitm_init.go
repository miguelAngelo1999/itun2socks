package executor

import (
	"path/filepath"

	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/mitm"
	"github.com/igoogolx/itun2socks/internal/tunnel"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// initMitmInterceptor initialises the MITM SSL inspection engine from persisted config.
// It is called at executor startup (New) so that the interceptor is ready before
// any TCP connections are processed.
func initMitmInterceptor() {
	cfg, err := configuration.GetSslInspectionSettings()
	if err != nil {
		log.Debugln("[MITM] failed to read ssl inspection config: " + err.Error())
		return
	}

	// Build inspection list from persisted entries
	inspectionList := mitm.NewInspectionList()
	entries, _ := configuration.GetInspectionList()
	mitmEntries := make([]mitm.InspectionListEntry, len(entries))
	for i, e := range entries {
		mitmEntries[i] = mitm.InspectionListEntry{Pattern: e.Pattern, Enabled: e.Enabled}
	}
	inspectionList.LoadFrom(mitmEntries)

	// Init CA if inspection is enabled
	if cfg.Enabled {
		configFilePath, err := configuration.GetConfigFilePath()
		if err == nil && configFilePath != "" {
			configDir := filepath.Dir(configFilePath)
			if _, err := mitm.GetOrInitCA(configDir); err != nil {
				log.Debugln("[MITM] CA init failed: " + err.Error())
			}
		}
	}

	// Create interceptor and register with tunnel
	ca := mitm.GetGlobalCA()
	interceptor := mitm.NewMitmInterceptor(ca, inspectionList)
	interceptor.SetEnabled(cfg.Enabled)
	mitm.SetGlobalInterceptor(interceptor)
	tunnel.SetMitmInterceptor(interceptor)

	entryCount := len(mitmEntries)
	if cfg.Enabled {
		log.Infoln("[MITM] SSL inspection enabled, inspection list: " + itoa(entryCount) + " entries, ca_nil=" + boolStr(ca == nil))
	} else {
		log.Debugln("[MITM] SSL inspection initialised (disabled), entries=" + itoa(entryCount))
	}
}

func boolStr(b bool) string {
	if b { return "true" }
	return "false"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 10)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
