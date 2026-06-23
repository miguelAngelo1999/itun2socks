//go:build windows

package routes

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// probeWindowsRegistry reads the IE/Edge system proxy from the Windows registry.
// Skips Lux's own 127.0.0.1 proxy.
func probeWindowsRegistry() DetectedProxy {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell.exe",
		"-noprofile", "-NonInteractive", "-command",
		`$k = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -EA SilentlyContinue;`+
			`if ($k.ProxyEnable -eq 1 -and $k.ProxyServer) { Write-Output $k.ProxyServer } else { Write-Output "" }`,
	).Output()
	if err != nil {
		return DetectedProxy{Found: false}
	}

	server := strings.TrimSpace(string(out))
	if server == "" {
		return DetectedProxy{Found: false}
	}

	// Skip Lux's own proxy
	if strings.HasPrefix(server, "127.0.0.1") || strings.HasPrefix(server, "localhost") {
		return DetectedProxy{Found: false}
	}

	// Parse host:port (may also be "http=host:port;https=host:port")
	// Take the first entry
	entry := server
	if idx := strings.Index(server, ";"); idx > 0 {
		entry = server[:idx]
	}
	// Strip protocol prefix like "http="
	if idx := strings.Index(entry, "="); idx >= 0 {
		entry = entry[idx+1:]
	}
	entry = strings.TrimSpace(entry)

	host, port := "", "8080"
	if strings.Contains(entry, ":") {
		parts := strings.SplitN(entry, ":", 2)
		host = strings.TrimSpace(parts[0])
		port = strings.TrimSpace(parts[1])
	} else {
		host = entry
	}

	if host == "" || host == "127.0.0.1" || host == "localhost" {
		return DetectedProxy{Found: false}
	}

	return DetectedProxy{Found: true, Host: host, Port: port, Scheme: "http", Source: "registry"}
}

// probeNetshWinhttp reads the WinHTTP proxy (set by GPO or DHCP, independent of IE settings).
func probeNetshWinhttp() DetectedProxy {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "netsh", "winhttp", "show", "proxy").Output()
	if err != nil {
		return DetectedProxy{Found: false}
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// Look for: "Proxy Server(s) :  host:port"
		lower := strings.ToLower(line)
		if strings.Contains(lower, "proxy server") && strings.Contains(line, ":") {
			// Extract after the last ":"... but be careful since host:port has ":"
			idx := strings.LastIndex(line, ":")
			if idx < 0 {
				continue
			}
			// Find the server:port substring
			colonIdx := strings.Index(line, " : ")
			if colonIdx < 0 {
				continue
			}
			server := strings.TrimSpace(line[colonIdx+3:])
			if server == "" || strings.EqualFold(server, "(null)") ||
				strings.EqualFold(server, "Direct access (no proxy server).") {
				continue
			}
			if strings.HasPrefix(server, "127.0.0.1") || strings.HasPrefix(server, "localhost") {
				continue
			}
			host, port := "", "8080"
			if strings.Contains(server, ":") {
				parts := strings.SplitN(server, ":", 2)
				host = strings.TrimSpace(parts[0])
				port = strings.TrimSpace(parts[1])
			} else {
				host = server
			}
			if host == "" {
				continue
			}
			return DetectedProxy{Found: true, Host: host, Port: port, Scheme: "http", Source: "winhttp"}
		}
	}
	return DetectedProxy{Found: false}
}
