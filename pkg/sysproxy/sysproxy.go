package sysproxy

import (
	"net"
	"os/exec"
	"strings"
	"sync"
)

// originalState stores the proxy settings per service before Lux modified them.
// On Clear(), these are restored exactly — not blindly set to defaults.
type serviceState struct {
	autoDiscovery bool // was ProxyAutoDiscovery on?
	autoproxy     bool // was AutoProxy (PAC) on?
	autoproxyURL  string
	httpEnabled   bool
	httpHost      string
	httpPort      string
	httpsEnabled  bool
	httpsHost     string
	httpsPort     string
}

var (
	savedStates   = make(map[string]*serviceState)
	savedStatesMu sync.Mutex
)

// saveOriginalState captures the current proxy settings for a service before we change them.
func saveOriginalState(svc string) {
	savedStatesMu.Lock()
	defer savedStatesMu.Unlock()
	if _, exists := savedStates[svc]; exists {
		return // already saved (don't overwrite with our own settings)
	}
	state := &serviceState{}

	// Auto-discovery
	if out, err := exec.Command("networksetup", "-getproxyautodiscovery", svc).Output(); err == nil {
		state.autoDiscovery = strings.Contains(strings.ToLower(string(out)), "on")
	}

	// Auto-proxy (PAC)
	if out, err := exec.Command("networksetup", "-getautoproxyurl", svc).Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "URL:") {
				state.autoproxyURL = strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
			}
			if strings.Contains(strings.ToLower(line), "enabled: yes") {
				state.autoproxy = true
			}
		}
	}

	// HTTP proxy
	if out, err := exec.Command("networksetup", "-getwebproxy", svc).Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Server:") {
				state.httpHost = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
			}
			if strings.HasPrefix(line, "Port:") {
				state.httpPort = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
			}
			if strings.Contains(strings.ToLower(line), "enabled: yes") {
				state.httpEnabled = true
			}
		}
	}

	// HTTPS proxy
	if out, err := exec.Command("networksetup", "-getsecurewebproxy", svc).Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Server:") {
				state.httpsHost = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
			}
			if strings.HasPrefix(line, "Port:") {
				state.httpsPort = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
			}
			if strings.Contains(strings.ToLower(line), "enabled: yes") {
				state.httpsEnabled = true
			}
		}
	}

	savedStates[svc] = state
}

// restoreOriginalState puts back exactly what was there before Lux started.
func restoreOriginalState(svc string) {
	savedStatesMu.Lock()
	state, exists := savedStates[svc]
	if exists {
		delete(savedStates, svc)
	}
	savedStatesMu.Unlock()

	if !exists {
		// No saved state — just disable everything (safe default)
		_ = DisableWebProxy(svc)
		return
	}

	// Restore HTTP proxy (or disable if it wasn't on)
	if state.httpEnabled && state.httpHost != "" && state.httpHost != "127.0.0.1" {
		_ = exec.Command("networksetup", "-setwebproxy", svc, state.httpHost, state.httpPort).Run()
	} else {
		_ = exec.Command("networksetup", "-setwebproxystate", svc, "off").Run()
	}

	// Restore HTTPS proxy
	if state.httpsEnabled && state.httpsHost != "" && state.httpsHost != "127.0.0.1" {
		_ = exec.Command("networksetup", "-setsecurewebproxy", svc, state.httpsHost, state.httpsPort).Run()
	} else {
		_ = exec.Command("networksetup", "-setsecurewebproxystate", svc, "off").Run()
	}

	// Restore auto-discovery
	if state.autoDiscovery {
		_ = exec.Command("networksetup", "-setproxyautodiscovery", svc, "on").Run()
	} else {
		_ = exec.Command("networksetup", "-setproxyautodiscovery", svc, "off").Run()
	}

	// Restore auto-proxy (PAC)
	if state.autoproxy && state.autoproxyURL != "" {
		_ = exec.Command("networksetup", "-setautoproxyurl", svc, state.autoproxyURL).Run()
		_ = exec.Command("networksetup", "-setautoproxystate", svc, "on").Run()
	} else {
		_ = exec.Command("networksetup", "-setautoproxystate", svc, "off").Run()
	}
}

func Set(addr string, activeInterface string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	services := getAllNetworkServices()
	if len(services) == 0 {
		return SetWebProxy(host, port, activeInterface)
	}
	for _, svc := range services {
		// Save original state BEFORE changing anything
		saveOriginalState(svc)
		// Set Lux proxy
		_ = SetWebProxy(host, port, svc)
		// Disable auto-proxy discovery so OS uses our explicit proxy
		_ = exec.Command("networksetup", "-setproxyautodiscovery", svc, "off").Run()
		_ = exec.Command("networksetup", "-setautoproxystate", svc, "off").Run()
	}
	return nil
}

func Clear(activeInterface string) error {
	services := getAllNetworkServices()
	if len(services) == 0 {
		return DisableWebProxy(activeInterface)
	}
	for _, svc := range services {
		// Restore exactly what was there before Lux started
		restoreOriginalState(svc)
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
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services
}
