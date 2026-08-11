package configuration

import (
	"fmt"
	"net"
	"time"

	"github.com/igoogolx/itun2socks/pkg/log"
)

// tryFailoverProxy switches to the first configured proxy that still has valid
// credentials and can reach its server. Returns true if a working proxy was found
// and selected, false if all are exhausted (caller should prompt the user).
func tryFailoverProxy(config Config, expiredIds []string) bool {
	expired := make(map[string]bool, len(expiredIds))
	for _, id := range expiredIds {
		expired[id] = true
	}

	currentSelected := config.Selected.Proxy

	for _, proxy := range config.Proxy {
		id, _ := proxy["id"].(string)
		if id == "" || id == currentSelected {
			continue
		}
		// Skip proxies whose credentials just expired
		if expired[id] {
			continue
		}
		// Skip proxies with no password (they may be configured but unusable)
		password, _ := proxy["password"].(string)
		if password == "" {
			// Also check if password might have been cleared by expiry
			if isExpired, _ := proxy["passwordExpired"].(bool); isExpired {
				continue
			}
		}

		// Quick connectivity check: can we reach the proxy server?
		server, _ := proxy["server"].(string)
		port := proxyPort(proxy)
		if server == "" || port == "" {
			continue
		}

		addr := net.JoinHostPort(server, port)
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			log.Debugln("[failover] proxy %s (%s) unreachable: %v", id, addr, err)
			continue
		}
		conn.Close()

		// This proxy is reachable — switch to it.
		log.Infoln("[failover] switching to proxy %s (%s) after credential expiry",
			id, proxy["name"])
		if err := SetSelectedId("proxy", id); err != nil {
			log.Warnln("[failover] failed to switch proxy: %v", err)
			continue
		}

		// Notify the UI about the switch (informational, not an error).
		if NotifyProxySwitch != nil {
			NotifyProxySwitch(id, fmt.Sprint(proxy["name"]))
		}
		return true
	}

	return false
}

func proxyPort(proxy map[string]any) string {
	switch v := proxy["port"].(type) {
	case float64:
		return fmt.Sprintf("%d", int(v))
	case int:
		return fmt.Sprintf("%d", v)
	case string:
		return v
	default:
		return ""
	}
}
