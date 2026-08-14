package executor

import (
	"fmt"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/internal/cfg"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/dns"
	localserver "github.com/igoogolx/itun2socks/internal/local_server"
	"github.com/igoogolx/itun2socks/internal/balancer"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/internal/tunnel/statistic"
	"github.com/igoogolx/itun2socks/pkg/clash/component/iface"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/network_iface"
	sTun "github.com/sagernet/sing-tun"
)

type DnsDetail struct {
	Addresses []string `json:"addresses"`
	Servers   []string `json:"servers"`
}

type Detail struct {
	DirectedInterfaceName   string    `json:"directedInterfaceName"`
	DirectedInterfaceV4Addr string    `json:"directedInterfaceV4Addr"`
	TunInterfaceName        string    `json:"tunInterfaceName"`
	LocalDns                DnsDetail `json:"localDns"`
	RemoteDns               DnsDetail `json:"remoteDns"`
	BoostDns                DnsDetail `json:"boostDns"`
	HubAddress              string    `json:"hubAddress"`
}

type TunClient struct {
	sync.RWMutex
	tun                  sTun.Tun
	stack                sTun.Stack
	localserver          localserver.Listener
	config               *cfg.Config
	isLocalServerEnabled bool
}

func (c *TunClient) RuntimeDetail(hubAddress string) (any, error) {
	networkInterface, err := iface.ResolveInterface(network_iface.GetDefaultInterfaceName())
	if err != nil {
		return nil, err
	}
	addr, err := networkInterface.PickIPv4Addr(nil)
	if err != nil {
		return nil, err
	}
	localDns := DnsDetail{Addresses: c.config.Rule.Dns.Local.Addresses, Servers: c.config.Rule.Dns.Local.GetServers()}
	remoteDns := DnsDetail{Addresses: c.config.Rule.Dns.Remote.Addresses, Servers: c.config.Rule.Dns.Remote.GetServers()}
	boostDns := DnsDetail{Addresses: c.config.Rule.Dns.Boost.Addresses, Servers: c.config.Rule.Dns.Boost.GetServers()}
	return &Detail{
		DirectedInterfaceV4Addr: addr.IP.String(),
		DirectedInterfaceName:   networkInterface.Name,
		TunInterfaceName:        c.config.Device.Name,
		LocalDns:                localDns,
		RemoteDns:               remoteDns,
		BoostDns:                boostDns,
		HubAddress:              hubAddress,
	}, nil
}

func (c *TunClient) Start() error {
	var err error
	if err = c.stack.Start(); err != nil {
		return fmt.Errorf("fail to start stack: %v", err)
	}
	if c.config.HijackDns.Enabled {

		_, err := dns.Hijack(c.config.HijackDns.NetworkService, constants.HijackedDns, c.config.HijackDns.AlwaysReset)
		if err != nil {
			return err
		}
	}
	if c.isLocalServerEnabled && c.config.LocalServer.AllowLan {
		err = c.localserver.Start()
		if err != nil {
			return err
		}
	}

	// Start PAC refresh loop — re-fetches and re-compiles every 30 minutes.
	pac.StartRefreshLoop(30 * time.Minute)

	// Apply WFP per-process bypass filters (Windows only).
	// On other platforms this is a no-op.
	ApplyProcessBypasses()

	// Register route-change handler: re-detect PAC and flush stale connections
	// when network interface changes (WireGuard/VPN reconnect, WiFi switch, etc.)
	network_iface.SetRouteChangeHandler(func(newIface string) {
		log.Infoln("[network] route changed to %s — flushing stale connections", newIface)
		statistic.DefaultManager.CloseAllConnections()
		pac.RefreshMyIP()
		// Re-apply PAC rules for the new network (runs in background, TUN is up)
		go detectAndApplyPac()
	})

	// Register flush handler for load balancer failover: when an interface becomes
	// unhealthy, all existing connections are flushed so apps reconnect on the healthy interface.
	balancer.SetFlushHandler(func() {
		log.Infoln("[balancer] failover flush — closing all connections")
		statistic.DefaultManager.CloseAllConnections()
	})

	return nil
}

func (c *TunClient) Close() error {
	var err error

	// Remove WFP bypass filters (Windows only). No-op on other platforms.
	CloseWfpBypass()

	// Stop refresh loop and clear PAC rules on disconnect.
	pac.StopRefreshLoop()
	pac.Clear()

	if c.config.HijackDns.Enabled {
		err := dns.Resume(c.config.HijackDns.NetworkService, c.config.HijackDns.AlwaysReset)
		if err != nil {
			return err
		}
	}
	statistic.DefaultManager.CloseAllConnections()
	if err = c.tun.Close(); err != nil {
		return err
	}
	err = network_iface.StopMonitor()
	if err != nil {
		return err
	}

	if c.isLocalServerEnabled && c.config.LocalServer.AllowLan {
		if err = c.localserver.Close(); err != nil {
			return err
		}
	}

	return nil
}

// applyMu guards detectAndApplyPac so concurrent calls (startup + route-change)
// don't race to fetch/compile the same PAC URL simultaneously.
var applyMu sync.Mutex

// detectAndApplyPac finds and applies the best available PAC URL.
// Priority: user-configured URL (from settings) > DHCP/registry auto-detect.
//
// On fetch/compile failure:
//   - If a user URL is configured: keep the last-known-good compiled PAC,
//     log a warning. Do NOT fall through to DHCP detection.
//   - If auto-detecting: clear PAC state (no fallback available).
func detectAndApplyPac() {
	if !applyMu.TryLock() {
		log.Debugln("[pac] detectAndApplyPac already running — skipping")
		return
	}
	defer applyMu.Unlock()

	// User-configured URL takes absolute priority.
	if userURL := pac.GetUserURL(); userURL != "" {
		_, err := pac.Apply(userURL)
		if err != nil {
			// Keep whatever was previously compiled — don't clear, don't fall back.
			log.Warnln("[pac] user PAC URL %s unreachable (%v) — keeping previous state", userURL, err)
		}
		return
	}

	// Auto-detect from DHCP option 252 (macOS) or registry AutoConfigURL (Windows).
	pacURL := pac.ProbeWPADUrl()
	if pacURL == "" {
		log.Debugln("[pac] no PAC URL detected on this network")
		return
	}

	_, err := pac.Apply(pacURL)
	if err != nil {
		log.Warnln("[pac] auto-detected PAC %s failed: %v", pacURL, err)
		pac.Clear()
		return
	}
	log.Infoln("[pac] auto-applied PAC from %s", pacURL)
}
