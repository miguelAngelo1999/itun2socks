//go:build windows

package routes

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"time"
)

// getDhcpDnsServers returns real DNS servers on Windows using ipconfig /all.
// Skips Lux's fake-IP range (198.18.x.x) and loopback addresses.
func getDhcpDnsServers() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ipconfig", "/all").Output()
	if err != nil {
		// Fallback: use net.InterfaceAddrs to find DNS via system resolver
		return getSystemDnsServers()
	}

	var servers []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// "DNS Servers . . . . . . . . . . . : 10.8.0.1"
		// or continuation lines like "                                     10.8.0.2"
		if strings.Contains(line, "DNS Servers") {
			if idx := strings.LastIndex(line, ":"); idx >= 0 {
				srv := strings.TrimSpace(line[idx+1:])
				if isValidDns(srv) && !seen[srv] {
					seen[srv] = true
					servers = append(servers, srv)
				}
			}
		} else if len(servers) > 0 && len(line) > 0 && !strings.Contains(line, ":") {
			// Continuation DNS server line
			srv := strings.TrimSpace(line)
			if isValidDns(srv) && !seen[srv] {
				seen[srv] = true
				servers = append(servers, srv)
			}
		}
	}
	return servers
}

func isValidDns(srv string) bool {
	if srv == "" {
		return false
	}
	ip := net.ParseIP(srv)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return false
	}
	s := ip.String()
	// Skip Lux fake-IP range
	if strings.HasPrefix(s, "198.18.") || strings.HasPrefix(s, "198.19.") {
		return false
	}
	return true
}

// getSystemDnsServers reads DNS config from the system resolver as fallback.
func getSystemDnsServers() []string {
	// Try to resolve using system DNS, return the configured servers
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, _ := net.DefaultResolver.LookupHost(ctx, "wpad")
	_ = addrs
	// Parse from registry as last resort
	regCtx, regCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer regCancel()
	out, err := exec.CommandContext(regCtx, "powershell.exe",
		"-noprofile", "-NonInteractive", "-command",
		`Get-DnsClientServerAddress -AddressFamily IPv4 | `+
			`Where-Object {$_.ServerAddresses -ne $null} | `+
			`ForEach-Object {$_.ServerAddresses} | `+
			`Where-Object {$_ -notmatch "^198\.(18|19)\." -and $_ -ne "127.0.0.1"} | `+
			`Select-Object -Unique`,
	).Output()
	if err != nil {
		return nil
	}
	var servers []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		srv := strings.TrimSpace(line)
		if isValidDns(srv) && !seen[srv] {
			seen[srv] = true
			servers = append(servers, srv)
		}
	}
	return servers
}
