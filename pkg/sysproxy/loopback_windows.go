//go:build windows

package sysproxy

import (
	"bytes"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/igoogolx/itun2socks/pkg/log"
	"golang.org/x/sys/windows"
)

var (
	loopbackMu          sync.Mutex
	loopbackLastApplied time.Time
	loopbackLastCount   int
)

const loopbackRefreshCooldown = 5 * time.Minute

// EnsureUWPLoopbackExemptions exempts installed UWP/MSIX packages from Windows
// AppContainer loopback isolation so Microsoft Store apps (such as iCloud for
// Windows and Microsoft Store) can reach Lux's local proxy on 127.0.0.1.
//
// Safe to call both on core startup and when enabling the system proxy: a
// mutex + cooldown prevents duplicate passes back-to-back.
func EnsureUWPLoopbackExemptions() {
	applyUWPLoopbackExemptions()
}

// applyUWPLoopbackExemptions exempts all installed UWP/MSIX (AppX) packages
// from Windows network isolation. Uses `-AllUsers -PackageTypeFilter All` so
// Microsoft Store MSIX apps (e.g. AppleInc.iCloud_*) and provisioned packages
// are all included when lux_core runs elevated via LuxCoreService (LocalSystem).
func applyUWPLoopbackExemptions() {
	loopbackMu.Lock()
	defer loopbackMu.Unlock()

	if loopbackLastCount > 0 && time.Since(loopbackLastApplied) < loopbackRefreshCooldown {
		return
	}

	if !windows.GetCurrentProcessToken().IsElevated() {
		log.Warnln("[loopback] skipping UWP loopback exemptions: lux_core is running non-elevated (enable LuxCoreService so Store/UWP apps like iCloud can connect)")
		return
	}

	cmd := exec.Command(
		"powershell.exe",
		"-NonInteractive",
		"-NoProfile",
		"-WindowStyle", "Hidden",
		"-Command",
		"$ProgressPreference = 'SilentlyContinue'; Get-AppxPackage -AllUsers -PackageTypeFilter All | Select-Object -ExpandProperty PackageFamilyName -Unique",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Warnln("[loopback] failed to list AppX packages: %v (stderr=%q)", err, strings.TrimSpace(stderr.String()))
		return
	}

	seen := make(map[string]struct{})
	var names []string
	for _, raw := range strings.Split(stdout.String(), "\n") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		names = append(names, name)
	}

	attempted := len(names)
	if attempted == 0 {
		log.Warnln("[loopback] Get-AppxPackage returned 0 packages — no UWP loopback exemptions applied")
		return
	}

	exempted := 0
	failed := 0
	firstErr := ""
	for _, name := range names {
		c := exec.Command("CheckNetIsolation.exe", "LoopbackExempt", "-a", "-n="+name)
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, err := c.CombinedOutput()
		if err == nil {
			exempted++
		} else {
			failed++
			if firstErr == "" {
				firstErr = strings.TrimSpace(string(out))
				if firstErr == "" {
					firstErr = err.Error()
				}
			}
		}
	}

	if exempted == 0 {
		log.Warnln("[loopback] exempted 0/%d UWP packages (failed=%d, sample=%q)", attempted, failed, firstErr)
		return
	}

	loopbackLastApplied = time.Now()
	loopbackLastCount = exempted
	if failed > 0 {
		log.Infoln("[loopback] exempted %d/%d UWP packages from network isolation (failed=%d, sample=%q)", exempted, attempted, failed, firstErr)
	} else {
		log.Infoln("[loopback] exempted %d/%d UWP packages from network isolation", exempted, attempted)
	}
}

// clearUWPLoopbackExemptions intentionally does NOT run
// `CheckNetIsolation LoopbackExempt -c` during normal disconnect/reconnect:
// `-c` wipes ALL Windows UWP loopback exemptions system-wide (including those
// owned by other apps/dev tools) and races with fast reconnects.
func clearUWPLoopbackExemptions() {}
