//go:build windows

package executor

import (
	"context"
	"os/exec"
	"time"
)

// saveOriginalWindowsProxy saves the current IE/Edge system proxy to
// HKCU:\Software\LuxProxy\OriginalProxyServer BEFORE lux overwrites it.
// This lets the detection endpoint find the corporate proxy even after
// lux has set 127.0.0.1:1090 as the system proxy.
func saveOriginalWindowsProxy() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "powershell.exe",
		"-noprofile", "-NonInteractive", "-command",
		`$k = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -EA SilentlyContinue;`+
			`$saved = Get-ItemProperty "HKCU:\Software\LuxProxy" -EA SilentlyContinue;`+
			`if ($k.ProxyEnable -eq 1 -and $k.ProxyServer -and `+
			`-not $k.ProxyServer.StartsWith("127.0.0.1") -and `+
			`-not $k.ProxyServer.StartsWith("localhost") -and `+
			`-not $saved.OriginalProxyServer) {`+
			`  if (-not (Test-Path "HKCU:\Software\LuxProxy")) { New-Item -Path "HKCU:\Software\LuxProxy" -Force | Out-Null };`+
			`  Set-ItemProperty "HKCU:\Software\LuxProxy" -Name OriginalProxyServer -Value $k.ProxyServer`+
			`}`,
	).Run()
}
