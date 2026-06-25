package dialer

import (
	"net"
	"syscall"

	"github.com/igoogolx/itun2socks/pkg/clash/component/iface"

	"golang.org/x/sys/unix"
)

type controlFn = func(network, address string, c syscall.RawConn) error

func bindControl(ifaceIdx int, chain controlFn) controlFn {
	return func(network, address string, c syscall.RawConn) (err error) {
		defer func() {
			if err == nil && chain != nil {
				err = chain(network, address, c)
			}
		}()

		ipStr, _, err := net.SplitHostPort(address)
		if err == nil {
			ip := net.ParseIP(ipStr)
			if ip != nil && !ip.IsGlobalUnicast() {
				return
			}
		}

		var innerErr error
		err = c.Control(func(fd uintptr) {
			// Resolve bare "tcp"/"udp" to tcp4/udp4 or tcp6/udp6 based on the address.
			// Without this, the switch has no matching case for bare "udp" connections
			// from TUN, leaving the socket unbound to the interface — causing the socket
			// to use [::] which fails with EINVAL when sending IPv4 UDP packets on macOS.
			resolvedNet := network
			if network == "udp" || network == "tcp" {
				if ipStr != "" {
					ip2 := net.ParseIP(ipStr)
					if ip2 != nil && ip2.To4() != nil {
						resolvedNet = network + "4"
					} else if ip2 != nil {
						resolvedNet = network + "6"
					} else {
						resolvedNet = network + "4"
					}
				} else {
					resolvedNet = network + "4"
				}
			}
			switch resolvedNet {
			case "tcp4", "udp4":
				innerErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifaceIdx)
			case "tcp6", "udp6":
				innerErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifaceIdx)
			}
		})

		if innerErr != nil {
			err = innerErr
		}

		return
	}
}

func bindIfaceToDialer(ifaceName string, dialer *net.Dialer, _ string, _ net.IP) error {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return err
	}

	dialer.Control = bindControl(ifaceObj.Index, dialer.Control)
	return nil
}

func bindIfaceToListenConfig(ifaceName string, lc *net.ListenConfig, _, address string) (string, error) {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return "", err
	}

	lc.Control = bindControl(ifaceObj.Index, lc.Control)
	return address, nil
}
