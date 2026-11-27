package routes

import (
	"net/http"

	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// DetectedProxy is one proxy or PAC-only entry discovered on the network.
type DetectedProxy struct {
	Host    string `json:"host"`
	Port    string `json:"port"`
	Type    string `json:"type"` // "http" or "socks5"
	PacURL  string `json:"pacUrl"`
	PacOnly bool   `json:"pacOnly,omitempty"`
}

// DetectedPAC is one valid PAC script URL discovered on the network.
// IsDynamic is true when the URL uses a DNS hostname (e.g. http://wpad/wpad.dat)
// rather than a static IP address (e.g. http://10.60.0.1:80/wpad.dat).
type DetectedPAC struct {
	URL       string `json:"url"`
	Source    string `json:"source"`
	IsDynamic bool   `json:"isDynamic"`
}

// detectProxies runs a multi-stage proxy & PAC auto-discovery pipeline:
//  1. OS-configured PAC / WPAD (DHCP option 252, macOS scutil, Windows Win32
//     registry across user SID/HKCU/HKLM, saved pre-Lux PAC URL) AND
//     self-hosted DNS WPAD discovery (http://wpad/wpad.dat, http://wpad/proxy.pac,
//     http://wpad.<suffix>/...). When both a dynamic DNS WPAD URL and a static
//     IP DHCP/OS PAC URL are available, the dynamic DNS URL is preferred first
//     and both are returned in `pacUrls`.
//  2. Full PAC evaluation (Goja JS) + comment-stripped static extraction of
//     PROXY / HTTP / HTTPS / SOCKS / SOCKS5 upstreams, plus PAC-only fallback
//     when a valid PAC script routes dynamically with no static server.
//  3. OS manual proxy settings (excluding Lux loopback) and environment vars.
//  4. Strict HTTP CONNECT LAN probe on physical gateways & private DNS servers
//     for non-WPAD corporate proxies (e.g. Squid on 3128/8080/8082/8888/8000),
//     plus checking if the discovered proxy host serves a PAC script itself.
//
// POST /proxies/detect
func detectProxies(w http.ResponseWriter, r *http.Request) {
	osCfg := pac.DetectOSProxyConfig()

	var pacCandidates []DetectedPAC
	seenPAC := make(map[string]bool)
	addPAC := func(rawURL, src string) {
		u := rawURL
		if u == "" || seenPAC[u] {
			return
		}
		seenPAC[u] = true
		pacCandidates = append(pacCandidates, DetectedPAC{
			URL:       u,
			Source:    src,
			IsDynamic: !pac.IsIPHostPACURL(u),
		})
	}

	// Stage 0a: Always probe DNS-hostname WPAD (http://wpad/wpad.dat,
	// http://wpad/proxy.pac, http://wpad.<suffix>/...) unless OS/DHCP already
	// gave us a dynamic hostname PAC URL — AND even if OS/DHCP gave a static IP
	// URL (like http://10.60.0.1:80/wpad.dat), probe DNS WPAD so roaming company
	// fleets discover http://wpad/wpad.dat too!
	if osCfg.PacURL != "" && !pac.IsIPHostPACURL(osCfg.PacURL) {
		addPAC(osCfg.PacURL, osCfg.PacSource)
	}
	if dnsURL := pac.ProbeHostnameWPADUrl(osCfg.DNSSuffixes); dnsURL != "" {
		addPAC(dnsURL, "wpad-dns")
	}
	if osCfg.PacURL != "" && pac.IsIPHostPACURL(osCfg.PacURL) {
		addPAC(osCfg.PacURL, osCfg.PacSource)
	}
	// Stage 0b: Only fall back to IP-based gateway / LAN DNS WPAD probing if no
	// PAC URL has been found yet.
	if len(pacCandidates) == 0 {
		if ipURL := pac.ProbeIPWPADUrl(osCfg.Gateways, osCfg.PrivateDNS); ipURL != "" {
			addPAC(ipURL, "wpad-probe")
		}
	}

	pacURL := ""
	source := ""
	if len(pacCandidates) > 0 {
		pacURL = pacCandidates[0].URL
		source = pacCandidates[0].Source
	}

	var proxies []DetectedProxy
	pacRuleCount := 0

	// Stage 1: If any PAC URL was found, fetch and parse/evaluate the highest-
	// priority one (dynamic DNS first), falling back to secondary candidates if
	// the first fails to fetch.
	if len(pacCandidates) > 0 {
		for idx, cand := range pacCandidates {
			log.Infoln("[detect-proxy] trying PAC URL (%s, dynamic=%v): %s", cand.Source, cand.IsDynamic, cand.URL)
			js, fetchErr := pac.Fetch(cand.URL)
			if fetchErr != nil {
				log.Warnln("[detect-proxy] could not fetch PAC %s: %v", cand.URL, fetchErr)
				continue
			}
			// Promote the candidate that actually fetched successfully as primary.
			pacURL = cand.URL
			source = cand.Source
			if idx > 0 {
				pacCandidates[0], pacCandidates[idx] = pacCandidates[idx], pacCandidates[0]
			}
			if rules, err := pac.Parse(js); err == nil {
				pacRuleCount = len(rules)
			}
			extracted := pac.ExtractProxiesFromPAC(js)
			for _, ep := range extracted {
				proxies = append(proxies, DetectedProxy{
					Host:   ep.Host,
					Port:   ep.Port,
					Type:   ep.Type,
					PacURL: pacURL,
				})
			}
			// Valid PAC script with no fixed proxy extracted (e.g. dynamic per-site
			// PAC or currently evaluating DIRECT): return as a PAC-only entry so the
			// user can still add the detected PAC script directly!
			if len(proxies) == 0 && pac.LooksLikePACScript(js) {
				proxies = append(proxies, DetectedProxy{
					Type:    "http",
					PacURL:  pacURL,
					PacOnly: true,
				})
			}
			break
		}
	}

	// Stage 2: OS manual proxies (skipping Lux loopback).
	if len(proxies) == 0 && len(osCfg.ManualProxies) > 0 {
		for _, mp := range osCfg.ManualProxies {
			proxies = append(proxies, DetectedProxy{
				Host:   mp.Host,
				Port:   mp.Port,
				Type:   mp.Type,
				PacURL: pacURL,
			})
			if source == "" {
				source = mp.Source
			}
		}
	}

	// Stage 3: Environment variables (HTTP_PROXY / HTTPS_PROXY / ALL_PROXY).
	if len(proxies) == 0 {
		for _, ep := range pac.EnvProxyEntries() {
			proxies = append(proxies, DetectedProxy{
				Host:   ep.Host,
				Port:   ep.Port,
				Type:   ep.Type,
				PacURL: pacURL,
			})
			if source == "" {
				source = ep.Source
			}
		}
	}

	// Stage 4: Strict HTTP CONNECT probe on physical gateways & private LAN DNS IPs.
	if len(proxies) == 0 {
		lanTargets := append([]string{}, osCfg.Gateways...)
		lanTargets = append(lanTargets, osCfg.PrivateDNS...)
		for _, lp := range pac.ProbeLANProxies(lanTargets) {
			proxies = append(proxies, DetectedProxy{
				Host:   lp.Host,
				Port:   lp.Port,
				Type:   lp.Type,
				PacURL: pacURL,
			})
			if source == "" {
				source = lp.Source
			}
		}
	}

	// Stage 5: If we discovered a proxy server without a PAC URL yet, check if
	// that proxy server itself serves /wpad.dat or /proxy.pac on port 80.
	if pacURL == "" && len(proxies) > 0 && proxies[0].Host != "" {
		if hostPac := pac.ProbeProxyHostPAC(proxies[0].Host); hostPac != "" {
			pacURL = hostPac
			addPAC(hostPac, "wpad-probe")
			if js, err := pac.Fetch(hostPac); err == nil {
				if rules, err := pac.Parse(js); err == nil {
					pacRuleCount = len(rules)
				}
			}
			for i := range proxies {
				proxies[i].PacURL = pacURL
			}
			log.Infoln("[detect-proxy] discovered companion PAC script on proxy host: %s", pacURL)
		}
	}

	if len(proxies) == 0 && pacURL == "" {
		render.Status(r, http.StatusOK)
		render.JSON(w, r, map[string]any{
			"pacUrl":       "",
			"pacUrls":      []DetectedPAC{},
			"pacRuleCount": 0,
			"source":       "",
			"proxies":      []DetectedProxy{},
			"message":      pac.NoPacFoundMessage(),
		})
		return
	}

	// Even if fetching the discovered PAC URL failed and no other proxy was found,
	// still return the PAC URL so the user can add it as a PAC-only proxy.
	if len(proxies) == 0 && pacURL != "" {
		proxies = append(proxies, DetectedProxy{
			Type:    "http",
			PacURL:  pacURL,
			PacOnly: true,
		})
	}

	if pacCandidates == nil {
		pacCandidates = []DetectedPAC{}
	}

	render.JSON(w, r, map[string]any{
		"pacUrl":       pacURL,
		"pacUrls":      pacCandidates,
		"pacRuleCount": pacRuleCount,
		"source":       source,
		"proxies":      proxies,
		"message":      "",
	})
}
