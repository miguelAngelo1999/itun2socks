//go:build windows

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/igoogolx/itun2socks/pkg/log"
)

// killStaleLuxCore finds and kills any other lux_core.exe process that is
// holding the proxy port (1090 by default). This prevents "address already
// in use" errors when a previous instance wasn't cleaned up properly.
func killStaleLuxCore() {
	myPid := os.Getpid()

	// Find PIDs of other lux_core.exe processes
	out, err := exec.Command("powershell.exe", "-noprofile", "-NonInteractive", "-command",
		`Get-Process -Name lux_core -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id`,
	).Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err != nil || pid == myPid {
			continue
		}
		// Kill the stale process
		log.Infoln("[STARTUP] killing stale lux_core pid=%d", pid)
		proc, err := os.FindProcess(pid)
		if err == nil {
			_ = proc.Kill()
		}
	}

	// Give the OS a moment to release the port
	if len(strings.Split(strings.TrimSpace(string(out)), "\n")) > 1 {
		time.Sleep(500 * time.Millisecond)
	}
}
