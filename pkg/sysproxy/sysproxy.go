package sysproxy

import (
	"net"
	"os/exec"
	"strings"
)

func Set(addr string, activeInterface string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	// Set proxy on all active network services, not just one
	services := getAllNetworkServices()
	if len(services) == 0 {
		// Fallback to single interface
		return SetWebProxy(host, port, activeInterface)
	}
	for _, svc := range services {
		// Ignore errors on individual services (some may not support proxy)
		_ = SetWebProxy(host, port, svc)
		// Disable auto-proxy discovery (WPAD/PAC) so the OS uses our explicit proxy
		// instead of fetching a PAC file that could override our settings
		_ = exec.Command("networksetup", "-setproxyautodiscovery", svc, "off").Run()
		_ = exec.Command("networksetup", "-setautoproxystate", svc, "off").Run()
	}
	return nil
}

func Clear(activeInterface string) error {
	// Clear proxy on all active network services
	services := getAllNetworkServices()
	if len(services) == 0 {
		return DisableWebProxy(activeInterface)
	}
	for _, svc := range services {
		_ = DisableWebProxy(svc)
		// Restore auto-proxy discovery when lux disconnects
		_ = exec.Command("networksetup", "-setproxyautodiscovery", svc, "on").Run()
	}
	return nil
}

// getAllNetworkServices returns all enabled network services from networksetup.
func getAllNetworkServices() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var services []string
	for i, line := range lines {
		if i == 0 {
			// First line is a header: "An asterisk (*) denotes..."
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Lines starting with * are disabled services - skip them
		if strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services
}
