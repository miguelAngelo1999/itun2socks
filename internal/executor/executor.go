package executor

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"time"

	"github.com/igoogolx/itun2socks/internal/cfg"
	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/cfg/local_server"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/conn"
	"github.com/igoogolx/itun2socks/internal/balancer"
	"github.com/igoogolx/itun2socks/internal/dns"
	"github.com/igoogolx/itun2socks/internal/events"
	localserver "github.com/igoogolx/itun2socks/internal/local_server"
	"github.com/igoogolx/itun2socks/internal/matcher"
	"github.com/igoogolx/itun2socks/internal/proxy_handler"
	"github.com/igoogolx/itun2socks/internal/tunnel"
	cResolver "github.com/igoogolx/itun2socks/pkg/clash/component/resolver"
	"github.com/igoogolx/itun2socks/pkg/clash/adapter"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/network_iface"
	"github.com/igoogolx/itun2socks/pkg/sysproxy"
	sTun "github.com/sagernet/sing-tun"
	"github.com/sirupsen/logrus"
)

type Client interface {
	Start() error
	Close() error
	RuntimeDetail(hubAddress string) (any, error)
}

// extractRawInterfaceName delegates to balancer.ExtractRawName.
func extractRawInterfaceName(name string) string {
	return balancer.ExtractRawName(name)
}

// InitPasswordExpiryHandler registers the callback that fires when a timed proxy
// password expires. If the expired proxy is currently selected, this automatically
// switches to the first available non-expired proxy so internet is not interrupted.
func InitPasswordExpiryHandler() {
	configuration.SetOnPasswordExpired(func(expiredId, _ string) {
		log.Infoln(log.FormatLog(log.ExecutorPrefix, "proxy password expired: %v"), expiredId)

		// Check if the expired proxy is currently selected
		selectedId, err := configuration.GetSelectedId("proxy")
		if err != nil || selectedId != expiredId {
			// Not selected — just broadcast the event, no switch needed
			broadcastProxyExpiredEvent(expiredId, "")
			return
		}

		// Find the first available proxy that isn't expired
		fallbackId := findFallbackProxy(expiredId)
		if fallbackId == "" {
			log.Warnln(log.FormatLog(log.ExecutorPrefix, "no fallback proxy found after expiry of %v"), expiredId)
			broadcastProxyExpiredEvent(expiredId, "")
			return
		}

		// Switch to the fallback proxy
		if err := configuration.SetSelectedId("proxy", fallbackId); err != nil {
			log.Warnln(log.FormatLog(log.ExecutorPrefix, "failed to switch to fallback proxy: %v"), err)
			broadcastProxyExpiredEvent(expiredId, "")
			return
		}

		// If lux is running, hot-swap the active proxy
		rawProxy, err := configuration.GetProxy(fallbackId)
		if err == nil {
			if p, err := adapter.ParseProxy(rawProxy); err == nil {
				conn.UpdateProxy(p)
			}
		}

		log.Infoln(log.FormatLog(log.ExecutorPrefix, "auto-switched from expired proxy %v to %v"), expiredId, fallbackId)
		broadcastProxyExpiredEvent(expiredId, fallbackId)
	})
}

// findFallbackProxy returns the ID of the first non-expired proxy that has
// working internet connectivity. Tries the previously-used proxy first,
// then tests all others in parallel with a 5s timeout.
func findFallbackProxy(excludeId string) string {
	proxies, err := configuration.GetProxies()
	if err != nil || len(proxies) == 0 {
		return ""
	}

	// Build a map for quick lookup
	proxyMap := map[string]map[string]any{}
	for _, p := range proxies {
		if id, _ := p["id"].(string); id != "" {
			proxyMap[id] = p
		}
	}

	// Try the previously-used proxy first (highest priority)
	prevId := configuration.GetPreviousProxyId()
	if prevId != "" && prevId != excludeId {
		if p, ok := proxyMap[prevId]; ok && !configuration.CheckPasswordExpiry(p) {
			parsed, err := adapter.ParseProxy(p)
			if err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, _, testErr := parsed.URLTest(ctx, "http://connectivitycheck.gstatic.com/generate_204")
				cancel()
				if testErr == nil {
					log.Infoln(log.FormatLog(log.ExecutorPrefix, "fallback: previous proxy %v is working"), prevId)
					return prevId
				}
				log.Debugln(log.FormatLog(log.ExecutorPrefix, "fallback: previous proxy %v failed: %v"), prevId, testErr)
			}
		}
	}

	// Test all remaining proxies in parallel
	type result struct {
		id    string
		works bool
	}
	results := make(chan result, len(proxies))

	tested := 0
	for _, p := range proxies {
		id, _ := p["id"].(string)
		if id == "" || id == excludeId || id == prevId {
			continue
		}
		if configuration.CheckPasswordExpiry(p) {
			continue
		}
		tested++
		go func(proxy map[string]any, proxyId string) {
			parsed, err := adapter.ParseProxy(proxy)
			if err != nil {
				results <- result{proxyId, false}
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _, err = parsed.URLTest(ctx, "http://connectivitycheck.gstatic.com/generate_204")
			results <- result{proxyId, err == nil}
		}(p, id)
	}

	if tested == 0 {
		return ""
	}

	working := map[string]bool{}
	for range tested {
		r := <-results
		if r.works {
			working[r.id] = true
		}
	}

	// Return in original proxy list order
	for _, p := range proxies {
		id, _ := p["id"].(string)
		if working[id] {
			return id
		}
	}
	return ""
}

// broadcastProxyExpiredEvent sends a proxy_expired event to all Flutter WebSocket clients.
func broadcastProxyExpiredEvent(expiredId, fallbackId string) {
	msg := fmt.Sprintf(
		`{"type":"proxy_expired","expiredId":"%s","fallbackId":"%s"}`,
		expiredId, fallbackId,
	)
	events.Broadcast([]byte(msg))
}

// UpdateDns rebuilds DNS resolvers from the current saved config and applies them live.
func UpdateDns() error {
	newCfg, err := cfg.NewTun(network_iface.GetDefaultInterfaceName())
	if err != nil {
		return err
	}
	dns.UpdateDnsMap(newCfg.Rule.Dns.Local.Client, newCfg.Rule.Dns.Remote.Client)
	dns.ResetCache()
	return nil
}

func UpdateRule() (string, error) {
	rawConfig, err := configuration.Read()
	if err != nil {
		return "", err
	}
	selectedRule, err := configuration.GetSelectedRule()
	if err != nil {
		return "", err
	}
	rEngine, err := rule_engine.New(selectedRule, rawConfig.Rules)
	if err != nil {
		return "", err
	}
	matcher.UpdateRuleEngine(rEngine)
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "update rule: %v"), selectedRule)
	dns.ResetCache()
	return selectedRule, nil
}

// cleanupTunAdapter removes any stale TUN adapter with the given name.
// This handles the "set IPv4 address: The object already exists" error
// that occurs when a previous lux_core was killed without proper cleanup.
func cleanupTunAdapter(name string) {
	if runtime.GOOS != "windows" {
		return
	}
	// Remove the stale interface IP assignment
	_ = exec.Command("netsh", "interface", "ip", "delete", "address",
		name, "10.255.0.1").Run()
	// Brief pause for the OS to release the adapter state
	time.Sleep(200 * time.Millisecond)
}

func newTun(isLocalServerEnabled bool) (*TunClient, error) {
	err := network_iface.StartMonitor()
	if err != nil {
		return nil, err
	}

	for {
		defaultInterface := network_iface.GetDefaultInterfaceName()
		if len(defaultInterface) != 0 {
			break
		}
		log.Infoln("%s", log.FormatLog(log.InitPrefix, "waiting for default interface name"))
		time.Sleep(1 * time.Second)
	}

	// Initialize load balancer if configured.
	// Interface names from Flutter may be "Friendly Name (en0)" format —
	// extract the raw OS name in parentheses.
	setting, _ := configuration.GetSetting()

	// Apply RestoreAutoDetect setting on Windows
	if runtime.GOOS == "windows" {
		sysproxy.RestoreAutoDetectOnExit = setting.RestoreAutoDetect
	}

	if setting.LoadBalance.Enabled && len(setting.LoadBalance.Interfaces) >= 2 {
		rawIfaces := make([]string, 0, len(setting.LoadBalance.Interfaces))
		for _, iface := range setting.LoadBalance.Interfaces {
			raw := extractRawInterfaceName(iface)
			if raw != "" {
				rawIfaces = append(rawIfaces, raw)
			}
		}
		if len(rawIfaces) >= 2 {
			balancer.Configure(rawIfaces, setting.LoadBalance.Strategy)
		} else {
			balancer.Configure(nil, "")
		}
	} else {
		balancer.Configure(nil, "")
	}

	config, err := cfg.NewTun(network_iface.GetDefaultInterfaceName())
	if err != nil {
		return nil, err
	}
	tunOptions := sTun.Options{
		Name:             config.Device.Name,
		MTU:              uint32(config.Device.Mtu),
		Inet4Address:     []netip.Prefix{config.Device.Gateway},
		AutoRoute:        true,
		StrictRoute:      true,
		Logger:           logrus.StandardLogger(),
		InterfaceMonitor: network_iface.GetDefaultInterfaceMonitor(),
	}
	// Detect and apply PAC rules BEFORE TUN starts — at this point the network
	// is still in its original state (no TUN interception), so wpad DNS resolution
	// and HTTP fetch work correctly without routing issues.
	detectAndApplyPac()

	// Clean up any stale adapter from a previous session before creating a new one.
	cleanupTunAdapter(config.Device.Name)
	tun, err := sTun.New(tunOptions)
	if err != nil {
		return nil, err
	}
	err = tun.Start()
	if err != nil {
		return nil, err
	}
	// Enable loopback for all UWP apps so their UDP traffic routes through TUN.
	// Without this, WhatsApp calls and similar UWP UDP traffic bypass the TUN.
	enableUWPLoopback()
	stack, err := sTun.NewStack("gvisor", sTun.StackOptions{
		Context:    context.Background(),
		Handler:    proxy_handler.New(tunnel.TcpQueue(), tunnel.UdpQueue()),
		TunOptions: tunOptions,
		Tun:        tun,
		UDPTimeout: 5 * time.Second,
		Logger:     logrus.StandardLogger(),
	})
	if err != nil {
		return nil, err
	}

	newLocalServer := localserver.NewListener(config.LocalServer.Addr, config.LocalServer.Port)
	var matchers = []conn.Matcher{
		config.Rule.ConnMatcher,
		conn.PacMatcher, // PAC DIRECT rules (no-op when no PAC is active)
	}
	if config.BlockQuic {
		matchers = append(matchers, conn.RejectQuicMather)
	}

	tunnel.UpdateShouldFindProcess(config.ShouldFindProcess)
	conn.UpdateConnMatcher(matchers)
	conn.UpdateIsFakeIpEnabled(config.FakeIp)
	conn.UpdateBlockQuic(config.BlockQuic)
	conn.UpdateProxy(config.Proxy)

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

	tunnel.UpdateShouldFindProcess(false)
	conn.UpdateConnMatcher([]conn.Matcher{
		config.Rule.ConnMatcher,
	})
	conn.UpdateProxy(config.Proxy)
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
