//go:build windows

package executor

import (
	"os/exec"
	"strings"

	"github.com/igoogolx/itun2socks/pkg/log"
)

// enableUWPLoopback uses checknetisolation to exempt all UWP app containers
// from network isolation, allowing their traffic (including UDP) to flow through
// the TUN virtual adapter. Without this, UWP apps like WhatsApp Desktop bypass
// the TUN and route directly, causing calls to fail in mixed/TUN mode.
//
// This runs once at TUN startup. It's the Windows equivalent of macOS's ability
// to intercept all app traffic at the kernel level.
func enableUWPLoopback() {
	// Get all installed app packages
	out, err := exec.Command("powershell.exe", "-noprofile", "-NonInteractive", "-command",
		"Get-AppxPackage | Select-Object -ExpandProperty PackageFamilyName").Output()
	if err != nil {
		log.Warnln(log.FormatLog(log.ExecutorPrefix, "failed to list UWP packages: %v"), err)
		return
	}

	packages := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, pkg := range packages {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		// Add loopback exemption for each package
		_ = exec.Command("checknetisolation", "loopbackexempt", "-a", "-n="+pkg).Run()
	}
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "enabled loopback exemption for %d UWP packages"), len(packages))
}
