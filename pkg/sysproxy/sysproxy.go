package sysproxy

import (
	"net"
)

func Set(addr string, activeInterface string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if err := SetWebProxy(host, port, activeInterface); err != nil {
		return err
	}
	setEnvProxy(addr)
	// Exempt all UWP apps from network isolation so they can reach the local proxy.
	go applyUWPLoopbackExemptions()
	return nil
}

func Clear(activeInterface string) error {
	clearEnvProxy()
	// Restore default UWP network isolation.
	go clearUWPLoopbackExemptions()
	return DisableWebProxy(activeInterface)
}

// envProxyVars is the canonical list of proxy env vars lux sets so that CLI
// tools (curl, git, pip, npm/node, wget, etc.) route through the local proxy.
// Both upper- and lower-case forms are set because different tools read
// different cases (curl reads lower, many others read upper).
var envProxyVars = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
	"http_proxy", "https_proxy", "all_proxy",
}

// setEnvProxy injects HTTP(S)_PROXY/ALL_PROXY and Node.js CA vars into the
// session environment. The mechanism is OS-specific (launchctl on macOS,
// HKCU\Environment + WM_SETTINGCHANGE on Windows) and lives in the per-OS
// files; this just delegates.
func setEnvProxy(addr string) {
	setEnvProxyPlatform(addr)
}

// clearEnvProxy removes the env vars set by setEnvProxy.
func clearEnvProxy() {
	clearEnvProxyPlatform()
}
