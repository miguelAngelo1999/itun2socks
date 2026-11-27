//go:build darwin

package pac

import (
	"net"
	"os/exec"
	"strings"

	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/sysproxy"
)

// DetectOSProxyConfig gathers macOS PAC/WPAD URLs, manual proxy settings,
// physical gateways, and DNS suffixes while safely skipping Lux's TUN device
// and loopback listener.
func DetectOSProxyConfig() OSProxyConfig {
	var cfg OSProxyConfig

	if saved := strings.TrimSpace(sysproxy.SavedPACURL()); strings.HasPrefix(saved, "http") {
		cfg.PacURL = saved
		cfg.PacSource = "saved-pac"
	}

	// Collect physical interfaces (never probe Lux's utun device).
	var ifaces []string
	if def := strings.TrimSpace(dialer.DefaultInterface.Load()); def != "" && !IsExcludedTunIface(def) && !strings.HasPrefix(def, "utun") {
		ifaces = appendUniqueStr(ifaces, def)
	}
	if routeIface := getDefaultIfaceName(); routeIface != "" && !IsExcludedTunIface(routeIface) && !strings.HasPrefix(routeIface, "utun") {
		ifaces = appendUniqueStr(ifaces, routeIface)
	}
	if netIfaces, err := net.Interfaces(); err == nil {
		for _, nif := range netIfaces {
			if nif.Flags&net.FlagUp == 0 || nif.Flags&net.FlagLoopback != 0 {
				continue
			}
			if !strings.HasPrefix(nif.Name, "en") {
				continue
			}
			addrs, _ := nif.Addrs()
			hasIPv4 := false
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() && !isExcludedIP(ipn.IP) {
					hasIPv4 = true
					break
				}
			}
			if hasIPv4 {
				ifaces = appendUniqueStr(ifaces, nif.Name)
			}
		}
	}

	// 1. DHCP Option 252 + domain_name + router across ALL active physical en* interfaces.
	for _, iface := range ifaces {
		out, err := exec.Command("ipconfig", "getpacket", iface).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if cfg.PacURL == "" && strings.Contains(line, "proxy_auto_discovery_url") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					u := strings.TrimSpace(parts[1])
					if strings.HasPrefix(u, "http") {
						log.Infoln("[wpad] found via DHCP option 252 (%s): %s", iface, u)
						cfg.PacURL = u
						cfg.PacSource = "dhcp-252"
					}
				}
			}
			if strings.Contains(line, "domain_name (string):") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					dom := strings.Trim(strings.TrimSpace(parts[1]), ".")
					if dom != "" {
						cfg.DNSSuffixes = appendUniqueStr(cfg.DNSSuffixes, dom)
					}
				}
			}
			if strings.Contains(line, "router (ip_mult):") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					raw := strings.Trim(strings.TrimSpace(parts[1]), "{}")
					for _, tok := range strings.Split(raw, ",") {
						gw := strings.TrimSpace(tok)
						if ip := net.ParseIP(gw); ip != nil && ip.To4() != nil && !isExcludedIP(ip) {
							cfg.Gateways = appendUniqueStr(cfg.Gateways, gw)
						}
					}
				}
			}
		}
	}

	// 2. scutil --proxy: ProxyAutoConfigURLString + manual HTTP/HTTPS/SOCKS proxies.
	if out, err := exec.Command("scutil", "--proxy").Output(); err == nil {
		kv := map[string]string{}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				kv[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		if cfg.PacURL == "" {
			if u := kv["ProxyAutoConfigURLString"]; strings.HasPrefix(u, "http") {
				log.Infoln("[wpad] found via scutil --proxy: %s", u)
				cfg.PacURL = u
				cfg.PacSource = "os-pac"
			}
		}
		if kv["HTTPEnable"] == "1" && kv["HTTPProxy"] != "" {
			port := kv["HTTPPort"]
			if port == "" {
				port = "8080"
			}
			if e, ok := ParseProxyURLOrAddr("http://"+kv["HTTPProxy"]+":"+port, "os-manual"); ok {
				cfg.ManualProxies = appendUniqueProxy(cfg.ManualProxies, e)
			}
		}
		if kv["HTTPSEnable"] == "1" && kv["HTTPSProxy"] != "" {
			port := kv["HTTPSPort"]
			if port == "" {
				port = "8080"
			}
			if e, ok := ParseProxyURLOrAddr("http://"+kv["HTTPSProxy"]+":"+port, "os-manual"); ok {
				cfg.ManualProxies = appendUniqueProxy(cfg.ManualProxies, e)
			}
		}
		if kv["SOCKSEnable"] == "1" && kv["SOCKSProxy"] != "" {
			port := kv["SOCKSPort"]
			if port == "" {
				port = "1080"
			}
			if e, ok := ParseProxyURLOrAddr("socks5://"+kv["SOCKSProxy"]+":"+port, "os-manual"); ok {
				cfg.ManualProxies = appendUniqueProxy(cfg.ManualProxies, e)
			}
		}
	}

	// 3. Physical gateway fallback + /etc/resolv.conf search domains & private DNS.
	if gw := getDefaultGateway(); gw != "" {
		if ip := net.ParseIP(gw); ip != nil && ip.To4() != nil && !isExcludedIP(ip) {
			cfg.Gateways = appendUniqueStr(cfg.Gateways, gw)
		}
	}
	servers, suffixes := discoverSystemDNS()
	for _, s := range suffixes {
		cfg.DNSSuffixes = appendUniqueStr(cfg.DNSSuffixes, s)
	}
	for _, srv := range servers {
		if ip := net.ParseIP(srv); ip != nil && ip.IsPrivate() && !isExcludedIP(ip) {
			cfg.PrivateDNS = appendUniqueStr(cfg.PrivateDNS, srv)
		}
	}

	return cfg
}
