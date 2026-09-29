package sysproxy

import (
	"net"
)

func Set(addr string, activeInterface string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	// Set the proxy on ALL active network services (Wi-Fi, USB Ethernet, etc.),
	// not just the one behind the default route. Otherwise plugging in a USB
	// ethernet adapter — or any service that isn't the current default — never
	// gets the proxy. getAllNetworkServices() returns nil on non-macOS (and if
	// networksetup fails), so those platforms fall back to the single-interface
	// call, which is correct: on Windows SetWebProxy ignores the interface and
	// sets the system-wide WinINET proxy anyway.
	services := getAllNetworkServices()
	if len(services) == 0 {
		if err := SetWebProxy(host, port, activeInterface); err != nil {
			return err
		}
	} else {
		for _, svc := range services {
			// Ignore per-service errors — some services don't support a proxy.
			_ = SetWebProxy(host, port, svc)
		}
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
	// Clear the proxy on ALL active network services (mirror of Set).
	services := getAllNetworkServices()
	if len(services) == 0 {
		return DisableWebProxy(activeInterface)
	}
	for _, svc := range services {
		_ = DisableWebProxy(svc)
	}
	return nil
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
