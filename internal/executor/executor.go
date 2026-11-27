package executor

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/igoogolx/itun2socks/internal/cfg"
	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/cfg/local_server"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/conn"
	"github.com/igoogolx/itun2socks/internal/dns"
	localserver "github.com/igoogolx/itun2socks/internal/local_server"
	"github.com/igoogolx/itun2socks/internal/matcher"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/internal/proxy_handler"
	"github.com/igoogolx/itun2socks/internal/tunnel"
	"github.com/igoogolx/itun2socks/pkg/clash/adapter"
	cResolver "github.com/igoogolx/itun2socks/pkg/clash/component/resolver"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/network_iface"
	sTun "github.com/sagernet/sing-tun"
	"github.com/sirupsen/logrus"
)

type Client interface {
	Start() error
	Close() error
	RuntimeDetail(hubAddress string) (any, error)
}

// UpdateRule rebuilds the rule engine from the store.
//
// Rules come from configuration.EffectiveRules, which flattens groups in order
// and omits rules that are disabled, in a disabled group, or broken. Reading
// Config.Rules here instead would reintroduce the flat representation whose
// "#" prefixes and string identity this rewrite removed.
func UpdateRule() (string, error) {
	selectedRule, err := configuration.GetSelectedRule()
	if err != nil {
		return "", err
	}

	effective, err := configuration.EffectiveRules()
	if err != nil {
		return "", err
	}

	// Named proxies must be declared to the parser, or a rule targeting one is
	// discarded as having an unknown policy.
	knownProxyIds, err := configuration.KnownProxyIds()
	if err != nil {
		return "", err
	}

	raw := make([]string, 0, len(effective))
	for _, r := range effective {
		if v := r.RawValue(); v != "" {
			raw = append(raw, v)
		}
	}

	rEngine, err := rule_engine.NewWithPolicies(selectedRule, raw, knownProxyIds)
	if err != nil {
		return "", err
	}
	matcher.UpdateRuleEngine(rEngine)
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "update rule: %v (%d active rules)"), selectedRule, len(raw))
	dns.ResetCache()
	return selectedRule, nil
}

// updateNamedProxies registers every configured proxy as individually dialable,
// so a rule whose policy is a proxy id can route through it.
func updateNamedProxies() {
	rawConfig, err := configuration.Read()
	if err != nil {
		log.Warnln(log.FormatLog(log.ExecutorPrefix, "cannot read config to register named proxies: %v"), err)
		return
	}
	byId := make(map[string]C.Proxy, len(rawConfig.Proxy))
	for _, rawProxy := range rawConfig.Proxy {
		id := fmt.Sprint(rawProxy["id"])
		if id == "" || id == "<nil>" {
			continue
		}
		p, err := adapter.ParseProxy(rawProxy)
		if err != nil {
			log.Warnln(log.FormatLog(log.ExecutorPrefix, "cannot dial proxy %v: %v"), id, err)
			continue
		}
		byId[id] = p
	}
	conn.UpdateNamedProxies(byId)
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "registered %d named proxies"), len(byId))

	// Populate the per-proxy PAC registry from any proxy that declares a pacUrl.
	pac.DefaultRegistry.Update(rawConfig.Proxy, "")

	// Store the selected proxy id so the PAC hook in NewTcpConn can look up its
	// PAC even when the policy is the generic PolicyProxy constant.
	conn.UpdateSelectedProxyId(rawConfig.Selected.Proxy)
}

const (
	defaultInterfaceWaitAttempts = 8
	defaultInterfaceWaitInterval = 1 * time.Second
)

func waitForDefaultInterface(getName func() string, maxAttempts int, interval time.Duration) (string, error) {
	for i := 0; i < maxAttempts; i++ {
		if name := getName(); len(name) != 0 {
			return name, nil
		}
		if i+1 < maxAttempts {
			log.Infoln("%s", log.FormatLog(log.InitPrefix, "waiting for default interface name"))
			time.Sleep(interval)
		}
	}
	return "", fmt.Errorf("no active default network interface")
}

func newTun(isLocalServerEnabled bool) (*TunClient, error) {
	err := network_iface.StartMonitor()
	if err != nil {
		return nil, err
	}

	defaultInterface, err := waitForDefaultInterface(
		network_iface.GetDefaultInterfaceName,
		defaultInterfaceWaitAttempts,
		defaultInterfaceWaitInterval,
	)
	if err != nil {
		_ = network_iface.StopMonitor()
		return nil, err
	}

	config, err := cfg.NewTun(defaultInterface)
	if err != nil {
		return nil, err
	}

	rawConfig, err := configuration.Read()
	if err != nil {
		return nil, err
	}

	pac.SetExcludedTunIface(config.Device.Name)
	if config.Rule.Dns.Local.Client != nil {
		pac.SetLocalLookup(func(ctx context.Context, host string) ([]string, error) {
			ips, err := config.Rule.Dns.Local.Client.LookupIPv4(ctx, host)
			if err != nil {
				return nil, err
			}
			var res []string
			for _, ip := range ips {
				res = append(res, ip.String())
			}
			return res, nil
		})
	}
	// Register DIRECT/PROXY dialers before PAC registry update so Local.Client
	// can dial immediately if it needs to resolve PAC URL hosts (e.g. wpad).
	conn.UpdateProxy(config.Proxy)
	pac.SetIsBypassed(IsBypassedFromTun)
	pac.DefaultRegistry.Update(rawConfig.Proxy, "")

	tunOptions := sTun.Options{
		Name:                    config.Device.Name,
		MTU:                     uint32(config.Device.Mtu),
		Inet4Address:            []netip.Prefix{config.Device.Gateway},
		AutoRoute:               true,
		StrictRoute:              false,
		Inet4RouteExcludeAddress: collectBypassCidrs(),
		Logger:                  logrus.StandardLogger(),
		InterfaceMonitor:        network_iface.GetDefaultInterfaceMonitor(),
	}
	tun, err := sTun.New(tunOptions)
	if err != nil {
		return nil, err
	}
	err = tun.Start()
	if err != nil {
		return nil, err
	}
	stackOpts := sTun.StackOptions{
		Context:    context.Background(),
		Handler:    proxy_handler.New(tunnel.TcpQueue(), tunnel.UdpQueue()),
		TunOptions: tunOptions,
		Tun:        tun,
		UDPTimeout: 5 * time.Minute,
		Logger:     logrus.StandardLogger(),
	}
	stack, err := sTun.NewStack("mixed", stackOpts)
	if err != nil && strings.Contains(err.Error(), "gVisor") {
		log.Warnln("[INIT] gVisor not compiled in, falling back to system TUN stack: %v", err)
		stack, err = sTun.NewStack("system", stackOpts)
	}
	if err != nil {
		return nil, err
	}

	newLocalServer := localserver.NewListener(config.LocalServer.Addr, config.LocalServer.Port)
	var matchers = []conn.Matcher{
		config.Rule.ConnMatcher,
	}
	if config.BlockQuic {
		matchers = append(matchers, conn.RejectQuicMather)
	}

	tunnel.UpdateShouldFindProcess(config.ShouldFindProcess)
	conn.UpdateConnMatcher(matchers)
	conn.UpdateIsFakeIpEnabled(config.FakeIp)
	updateNamedProxies()
	conn.UpdateProxyWithId(config.Proxy, rawConfig.Selected.Proxy)

	log.Infoln(log.FormatLog(log.ExecutorPrefix, "set proxy: %v"), config.Proxy.Name())
	dns.UpdateDnsMap(config.Rule.Dns.Local.Client, config.Rule.Dns.Remote.Client)
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "set dns, local: %v, remote: %v"), config.Rule.Dns.Local.Addresses, config.Rule.Dns.Remote.Addresses)
	_, err = UpdateRule()
	if err != nil {
		return nil, err
	}

	return &TunClient{
		stack:                stack,
		tun:                  tun,
		localserver:          newLocalServer,
		config:               config,
		isLocalServerEnabled: isLocalServerEnabled,
	}, nil
}

func newSysProxy() (*SystemProxyClient, error) {
	config, err := cfg.NewSystemProxy()
	if err != nil {
		return nil, err
	}

	rawConfig, err := configuration.Read()
	if err == nil {
		pac.DefaultRegistry.Update(rawConfig.Proxy, "")
	}

	tunnel.UpdateShouldFindProcess(false)
	conn.UpdateConnMatcher([]conn.Matcher{
		config.Rule.ConnMatcher,
	})
	updateNamedProxies()
	conn.UpdateProxyWithId(config.Proxy, rawConfig.Selected.Proxy)
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "set proxy: %v"), config.Proxy.Name())
	_, err = UpdateRule()
	if err != nil {
		return nil, err
	}

	newLocalServer := localserver.NewListener(config.LocalServer.Addr, config.LocalServer.Port)
	return &SystemProxyClient{
		localserver:     newLocalServer,
		activeInterface: config.ActiveInterface,
	}, nil
}

func newMixed() (Client, error) {
	rawConfig, err := configuration.Read()
	if err != nil {
		return nil, err
	}
	localServerConfig := local_server.New(rawConfig.Setting.LocalServer)
	newLocalServer := localserver.NewListener(localServerConfig.Addr, localServerConfig.Port)
	sysClient := &SystemProxyClient{
		localserver:     newLocalServer,
		activeInterface: rawConfig.Setting.HijackDns.NetworkService,
	}

	tunClient, err := newTun(false)
	if err != nil {
		return nil, err
	}
	return &MixedProxyClient{
		sysClient: sysClient,
		tunClient: tunClient,
	}, nil
}

func New() (Client, error) {
	cResolver.DefaultResolver = nil
	rawConfig, err := configuration.Read()
	if err != nil {
		return nil, err
	}
	if rawConfig.Setting.Mode == "tun" {
		return newTun(true)
	}
	if rawConfig.Setting.Mode == "system" {
		return newSysProxy()
	}
	if rawConfig.Setting.Mode == "mixed" {
		return newMixed()
	}
	return nil, fmt.Errorf("invalid proxy mode: %v", rawConfig.Setting.Mode)
}
