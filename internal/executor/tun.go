package executor

import (
	"fmt"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/internal/cfg"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/dns"
	localserver "github.com/igoogolx/itun2socks/internal/local_server"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/internal/tunnel/statistic"
	"github.com/igoogolx/itun2socks/pkg/clash/component/iface"
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

	// Apply WFP per-process bypasses (Windows only — no-op on macOS).
	ApplyProcessBypasses()

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

	// Start the PAC refresh loop so per-proxy PAC scripts stay current.
	pac.DefaultRegistry.StartRefreshLoop(30*time.Minute, "")

	return nil
}

func (c *TunClient) Close() error {
	var err error

	// Clean up WFP bypass filters (Windows only — no-op on macOS).
	CloseWfpBypass()

	// Stop PAC refresh and clear the registry on disconnect.
	pac.DefaultRegistry.StopRefreshLoop()
	pac.DefaultRegistry.Clear()

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
