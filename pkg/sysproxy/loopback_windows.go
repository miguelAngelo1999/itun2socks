//go:build windows

package sysproxy

import (
	"os/exec"
	"strings"

	"github.com/igoogolx/itun2socks/pkg/log"
)

// applyUWPLoopbackExemptions exempts all installed UWP (AppX) packages from
// the Windows network isolation that normally prevents them from connecting
// to localhost. This is required for UWP apps to use a local proxy.
//
// Equivalent to the PowerShell one-liner:
//   Get-AppxPackage -AllUsers |
//     ForEach-Object { CheckNetIsolation LoopbackExempt -a -n="$($_.PackageFamilyName)" }
//
// lux_core runs as SYSTEM (elevated) so CheckNetIsolation succeeds without
// additional UAC prompts.
func applyUWPLoopbackExemptions() {
	// Get all installed package family names via PowerShell
	out, err := exec.Command("powershell", "-NonInteractive", "-NoProfile", "-Command",
		"Get-AppxPackage -AllUsers | Select-Object -ExpandProperty PackageFamilyName").Output()
	if err != nil {
		log.Warnln("[loopback] failed to list AppX packages: %v", err)
		return
	}

	names := strings.Split(strings.TrimSpace(string(out)), "\n")
	exempted := 0
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if err := exec.Command("CheckNetIsolation", "LoopbackExempt", "-a",
			"-n="+name).Run(); err == nil {
			exempted++
		}
	}
	log.Infoln("[loopback] exempted %d UWP packages from network isolation", exempted)
}

// clearUWPLoopbackExemptions removes all loopback exemptions added by lux.
// This restores the default isolation state when the proxy stops.
func clearUWPLoopbackExemptions() {
	if err := exec.Command("CheckNetIsolation", "LoopbackExempt", "-c").Run(); err != nil {
		log.Warnln("[loopback] failed to clear loopback exemptions: %v", err)
		return
	}
	log.Infoln("[loopback] cleared all UWP loopback exemptions")
}
