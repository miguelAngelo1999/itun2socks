package network_iface

import (
	"context"
	"net"

	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	"github.com/igoogolx/itun2socks/pkg/log"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sirupsen/logrus"
	"go.uber.org/atomic"
)

var defaultInterfaceName = atomic.NewString("")
var defaultInterfaceMonitor tun.DefaultInterfaceMonitor
var networkUpdateMonitor tun.NetworkUpdateMonitor

func GetDefaultInterfaceName() string {
	return defaultInterfaceName.Load()
}

func GetDefaultInterfaceMonitor() tun.DefaultInterfaceMonitor {
	return defaultInterfaceMonitor
}

type ErrorHandler struct {
}

func (e ErrorHandler) NewError(_ context.Context, err error) {
	log.Errorln(log.FormatLog(log.ExecutorPrefix, "network interface monitor: %v"), err)
}

var monitorCallback *list.Element[tun.DefaultInterfaceUpdateCallback]

func StartMonitor() error {
	// Stop any existing monitor before starting a new one.
	// Prevents resource leaks and conflicts when StartMonitor is called
	// repeatedly after connectivity blips or lux_core restarts.
	if networkUpdateMonitor != nil || defaultInterfaceMonitor != nil {
		_ = StopMonitor()
	}

	setting, err := configuration.GetSetting()
	if err != nil {
		return err
	}
	if len(setting.DefaultInterface) != 0 {
		update(setting.DefaultInterface)
		// Create a NetworkUpdateMonitor and DefaultInterfaceMonitor even when
		// DefaultInterface is explicitly configured — sing-tun requires a non-nil
		// InterfaceMonitor for TUN/mixed mode (NativeTun.Start calls RegisterMyInterface).
		networkUpdateMonitor, err = tun.NewNetworkUpdateMonitor(logrus.StandardLogger())
		if err != nil {
			return E.Cause(err, "create NetworkUpdateMonitor")
		}
		err = networkUpdateMonitor.Start()
		if err != nil {
			return E.Cause(err, "start NetworkUpdateMonitor")
		}
		defaultInterfaceMonitor, err = tun.NewDefaultInterfaceMonitor(
			networkUpdateMonitor,
			logrus.StandardLogger(),
			tun.DefaultInterfaceMonitorOptions{
				OverrideAndroidVPN: true,
				InterfaceFinder:    control.NewDefaultInterfaceFinder(),
			})
		if err != nil {
			return E.Cause(err, "create DefaultInterfaceMonitor")
		}
		monitorCallback = defaultInterfaceMonitor.RegisterCallback(func(defaultInterface *control.Interface, flags int) {
			if defaultInterface != nil {
				update(defaultInterface.Name)
			}
		})
		err = defaultInterfaceMonitor.Start()
		if err != nil {
			return E.Cause(err, "start DefaultInterfaceMonitor")
		}
		return nil
	}
	networkUpdateMonitor, err = tun.NewNetworkUpdateMonitor(logrus.StandardLogger())
	if err != nil {
		err = E.Cause(err, "create NetworkUpdateMonitor")
		return err
	}
	err = networkUpdateMonitor.Start()
	if err != nil {
		err = E.Cause(err, "start NetworkUpdateMonitor")
		return err
	}

	defaultInterfaceMonitor, err = tun.NewDefaultInterfaceMonitor(
		networkUpdateMonitor,
		logrus.StandardLogger(),
		tun.DefaultInterfaceMonitorOptions{
			OverrideAndroidVPN: true,
			InterfaceFinder:    control.NewDefaultInterfaceFinder(),
		})
	if err != nil {
		err = E.Cause(err, "create DefaultInterfaceMonitor")
		return err
	}
	monitorCallback = defaultInterfaceMonitor.RegisterCallback(func(defaultInterface *control.Interface, flags int) {
		//FIXME: flags?
		if defaultInterface != nil {
			update(defaultInterface.Name)
		}
	})
	err = defaultInterfaceMonitor.Start()
	if err != nil {
		return err
	}
	if defaultInterfaceMonitor.DefaultInterface() != nil {
		update(defaultInterfaceMonitor.DefaultInterface().Name)
	}
	return nil
}

func StopMonitor() error {
	defer func() {
		defaultInterfaceMonitor = nil
		networkUpdateMonitor = nil
		monitorCallback = nil
	}()
	if monitorCallback != nil {
		defaultInterfaceMonitor.UnregisterCallback(monitorCallback)
	}
	if networkUpdateMonitor != nil {
		err := networkUpdateMonitor.Close()
		if err != nil {
			return err
		}
	}
	if defaultInterfaceMonitor != nil {
		err := defaultInterfaceMonitor.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// onRouteChange is called when the default network interface changes.
// Register a handler to be notified (e.g. to flush stale connections).
var onRouteChange func(newIface string)

// SetRouteChangeHandler registers a callback for default interface changes.
// The callback is called with the new interface name whenever routing changes
// (e.g. WireGuard reconnect, WiFi switch, Ethernet plug/unplug).
func SetRouteChangeHandler(fn func(string)) {
	onRouteChange = fn
}

func update(name string) {
	prev := defaultInterfaceName.Load()
	defaultInterfaceName.Store(name)
	dialer.DefaultInterface.Store(name)
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "update default interface: %v"), name)
	// Notify route change handler if the interface actually changed
	if prev != name && onRouteChange != nil {
		go onRouteChange(name)
	}
}

func getLocalIp() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Debugln(log.FormatLog(log.ExecutorPrefix, "close connection error in getLocalIp:"), err)
		}
	}(conn)

	localAddress := conn.LocalAddr().(*net.UDPAddr)

	return localAddress.IP, nil
}

func GetLanV4Address() string {
	ip, err := getLocalIp()
	if err != nil {
		return ""
	}
	return ip.String()
}
