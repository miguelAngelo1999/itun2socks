package executor

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"

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

	// Register route-change handler: re-detect PAC and flush stale connections
	// when network interface changes (WireGuard/VPN reconnect, WiFi switch, etc.)
	network_iface.SetRouteChangeHandler(func(newIface string) {
		log.Infoln("[network] route changed to %s — flushing stale connections", newIface)
		statistic.DefaultManager.CloseAllConnections()
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

	// Clear PAC rules on disconnect
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

// detectAndApplyPac finds the WPAD/DHCP PAC URL for the current network
// and applies its DIRECT rules so internal resources bypass the proxy.
func detectAndApplyPac() {
	var pacURL string

	if runtime.GOOS == "darwin" {
		// Check DHCP option 252 (proxy_auto_discovery_url) on the default interface
		defaultIface := network_iface.GetDefaultInterfaceName()
		if defaultIface != "" {
			out, err := exec.Command("ipconfig", "getpacket", defaultIface).Output()
			if err == nil {
				for _, line := range strings.Split(string(out), "\n") {
					if strings.Contains(line, "proxy_auto_discovery_url") {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) == 2 {
							pacURL = strings.TrimSpace(parts[1])
						}
					}
				}
			}
		}
	}
	// TODO: Windows — check registry for AutoConfigURL
	if runtime.GOOS == "windows" {
		out, err := exec.Command("powershell.exe",
			"-noprofile", "-NonInteractive", "-command",
			`(Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -EA SilentlyContinue).AutoConfigURL`,
		).Output()
		if err == nil {
			url := strings.TrimSpace(string(out))
			if url != "" && strings.HasPrefix(url, "http") {
				pacURL = url
			}
		}
	}

	if pacURL == "" {
		log.Debugln("[pac] no PAC URL detected on this network")
		return
	}

	rules, err := pac.Apply(pacURL)
	if err != nil {
		log.Warnln("[pac] failed to apply PAC from %s: %v", pacURL, err)
		return
	}
	log.Infoln("[pac] auto-applied %d DIRECT rules from %s", len(rules), pacURL)
}
