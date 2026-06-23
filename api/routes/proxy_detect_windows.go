//go:build windows

package routes

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// probeWindowsRegistry detects the corporate proxy on Windows using multiple methods:
// 1. Saved pre-lux proxy (from HKCU:\Software\LuxProxy if previously saved)
// 2. Manual proxy in registry (if not lux's own 127.0.0.1)
// 3. Windows auto-detect / PAC via GetSystemWebProxy (handles WPAD/PAC exactly like Windows)
func probeWindowsRegistry() DetectedProxy {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell.exe",
		"-noprofile", "-NonInteractive", "-command",
		// Method 1: saved original proxy
		`$saved = (Get-ItemProperty "HKCU:\Software\LuxProxy" -EA SilentlyContinue).OriginalProxyServer;`+
			`if ($saved -and -not $saved.StartsWith("127.0.0.1")) { Write-Output $saved; exit 0 };`+
			// Method 2: manual registry proxy
			`$k = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -EA SilentlyContinue;`+
			`if ($k.ProxyEnable -eq 1 -and $k.ProxyServer -and `+
			`-not $k.ProxyServer.StartsWith("127.0.0.1") -and -not $k.ProxyServer.StartsWith("localhost")) `+
			`{ Write-Output $k.ProxyServer; exit 0 };`+
			// Method 3: Windows auto-detect (WPAD/PAC) - GetSystemWebProxy resolves it
			`$proxy = [System.Net.WebRequest]::GetSystemWebProxy();`+
			`$uri = [Uri]"https://www.microsoft.com";`+
			`$proxyUri = $proxy.GetProxy($uri);`+
			`if ($proxyUri -ne $null -and $proxyUri.Host -ne $uri.Host -and `+
			`-not $proxyUri.Host.StartsWith("127.0.0.1") -and -not $proxyUri.Host.StartsWith("localhost")) `+
			`{ Write-Output "$($proxyUri.Host):$($proxyUri.Port)"; exit 0 };`+
			`Write-Output ""`,
	).Output()
	if err != nil {
		return DetectedProxy{Found: false}
	}

	server := strings.TrimSpace(string(out))
	if server == "" {
		return DetectedProxy{Found: false}
	}
	return parseProxyServer(server, "windows-autodetect")
}

// parseProxyServer parses "host:port" or "http=host:port;https=..." into a DetectedProxy.
func parseProxyServer(server, source string) DetectedProxy {
	entry := server
	if idx := strings.Index(server, ";"); idx > 0 {
		entry = server[:idx]
	}
	if idx := strings.Index(entry, "="); idx >= 0 {
		entry = entry[idx+1:]
	}
	entry = strings.TrimSpace(entry)
	if entry == "" || strings.HasPrefix(entry, "127.0.0.1") || strings.HasPrefix(entry, "localhost") {
		return DetectedProxy{Found: false}
	}
	host, port := "", "8080"
	if strings.Contains(entry, ":") {
		parts := strings.SplitN(entry, ":", 2)
		host = strings.TrimSpace(parts[0])
		port = strings.TrimSpace(parts[1])
	} else {
		host = entry
	}
	if host == "" {
		return DetectedProxy{Found: false}
	}
	return DetectedProxy{Found: true, Host: host, Port: port, Scheme: "http", Source: source}
}

// probeNetshWinhttp reads the WinHTTP proxy (GPO/DHCP, independent of IE settings).
func probeNetshWinhttp() DetectedProxy {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "netsh", "winhttp", "show", "proxy").Output()
	if err != nil {
		return DetectedProxy{Found: false}
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		colonIdx := strings.Index(line, " : ")
		if colonIdx < 0 {
			continue
		}
		lower := strings.ToLower(line[:colonIdx])
		if !strings.Contains(lower, "proxy server") {
			continue
		}
		server := strings.TrimSpace(line[colonIdx+3:])
		if server == "" || strings.EqualFold(server, "(null)") ||
			strings.Contains(strings.ToLower(server), "direct") ||
			strings.HasPrefix(server, "127.0.0.1") || strings.HasPrefix(server, "localhost") {
			continue
		}
		return parseProxyServer(server, "winhttp")
	}
	return DetectedProxy{Found: false}
}
