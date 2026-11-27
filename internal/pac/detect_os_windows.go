//go:build windows

package pac

import (
	"net"
	"strings"

	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/sysproxy"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const winInetSettingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// DetectOSProxyConfig reads Windows WinINET proxy / PAC settings directly from
// the Win32 registry (logged-in user's HKEY_USERS\<SID> hive first so
// LuxCoreService running as LocalSystem sees the real desktop user's settings,
// then HKCU, then HKLM) plus physical adapter gateways, DNS suffixes, and LAN
// DNS servers via native winipcfg — zero PowerShell spawns.
func DetectOSProxyConfig() OSProxyConfig {
	var cfg OSProxyConfig

	// 1. If Lux is currently connected and temporarily replaced AutoConfigURL,
	// recover the original user PAC URL first.
	if saved := strings.TrimSpace(sysproxy.SavedPACURL()); strings.HasPrefix(saved, "http") {
		log.Infoln("[wpad] found via saved pre-Lux AutoConfigURL: %s", saved)
		cfg.PacURL = saved
		cfg.PacSource = "saved-pac"
	}

	// 2. Native Win32 registry reads: user SID hive -> HKCU -> HKLM.
	type regTarget struct {
		root  registry.Key
		path  string
		label string
	}
	var targets []regTarget
	if sid := strings.TrimSpace(sysproxy.GetTargetUserSID()); sid != "" {
		targets = append(targets, regTarget{
			root:  registry.USERS,
			path:  sid + `\` + winInetSettingsPath,
			label: "HKU\\" + sid,
		})
	}
	targets = append(targets,
		regTarget{root: registry.CURRENT_USER, path: winInetSettingsPath, label: "HKCU"},
		regTarget{root: registry.LOCAL_MACHINE, path: winInetSettingsPath, label: "HKLM"},
	)

	for _, t := range targets {
		k, err := registry.OpenKey(t.root, t.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		if cfg.PacURL == "" {
			if u, _, err := k.GetStringValue("AutoConfigURL"); err == nil {
				u = strings.TrimSpace(u)
				if strings.HasPrefix(u, "http") {
					log.Infoln("[wpad] found via Windows registry (%s): %s", t.label, u)
					cfg.PacURL = u
					cfg.PacSource = "os-pac"
				}
			}
		}
		if enabled, _, err := k.GetIntegerValue("ProxyEnable"); err == nil && enabled == 1 {
			if ps, _, err := k.GetStringValue("ProxyServer"); err == nil {
				for _, e := range ParseWindowsProxyServer(ps, "os-manual") {
					cfg.ManualProxies = appendUniqueProxy(cfg.ManualProxies, e)
				}
			}
		}
		_ = k.Close()
	}

	// 3. Native physical adapter discovery: DNS suffixes, private DNS servers,
	// and IPv4 default gateways (skipping Lux Wintun / loopback adapters).
	servers, suffixes := discoverSystemDNS()
	for _, s := range suffixes {
		cfg.DNSSuffixes = appendUniqueStr(cfg.DNSSuffixes, s)
	}
	for _, srv := range servers {
		if ip := net.ParseIP(srv); ip != nil && ip.IsPrivate() && !isExcludedIP(ip) {
			cfg.PrivateDNS = appendUniqueStr(cfg.PrivateDNS, srv)
		}
	}

	if adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways); err == nil {
		excludedTunMu.RLock()
		tunName := strings.ToLower(strings.TrimSpace(excludedTunIface))
		excludedTunMu.RUnlock()

		for _, a := range adapters {
			if a == nil || a.OperStatus != winipcfg.IfOperStatusUp {
				continue
			}
			if a.IfType == winipcfg.IfTypeSoftwareLoopback {
				continue
			}
			friendly := strings.ToLower(a.FriendlyName())
			desc := strings.ToLower(a.Description())
			if (tunName != "" && friendly == tunName) ||
				strings.HasPrefix(friendly, "utun") ||
				strings.Contains(desc, "itun2socks") ||
				strings.Contains(desc, "wintun") {
				continue
			}
			for gw := a.FirstGatewayAddress; gw != nil; gw = gw.Next {
				ip := gw.Address.IP()
				if ip == nil {
					continue
				}
				ip4 := ip.To4()
				if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() || isExcludedIP(ip4) {
					continue
				}
				cfg.Gateways = appendUniqueStr(cfg.Gateways, ip4.String())
			}
		}
	}

	return cfg
}
