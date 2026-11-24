package dialer

import (
	"encoding/binary"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"github.com/igoogolx/itun2socks/pkg/clash/component/iface"

	"golang.org/x/sys/windows"
)

const (
	IP_UNICAST_IF   = 31
	IPV6_UNICAST_IF = 31
	// SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12 (0x9800000C)
	sioUdpConnReset = windows.IOC_IN | windows.IOC_VENDOR | 12
)

// disableUdpConnReset disables Winsock's default behavior of reporting ICMP
// Port Unreachable as WSAECONNRESET on the next RecvFrom of an unconnected UDP
// socket. Without this, one closed ICE/STUN candidate poisons the entire shared
// UDP relay socket for WhatsApp/WebRTC calls.
func disableUdpConnReset(handle windows.Handle) {
	var zero uint32
	var bytesReturned uint32
	_ = windows.WSAIoctl(
		handle,
		sioUdpConnReset,
		(*byte)(unsafe.Pointer(&zero)),
		uint32(unsafe.Sizeof(zero)),
		nil,
		0,
		&bytesReturned,
		nil,
		0,
	)
}

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
			if strings.HasPrefix(network, "udp") {
				disableUdpConnReset(windows.Handle(fd))
			}
			if ipStr == "" && strings.HasPrefix(network, "udp") {
				// When listening udp ":0", we should bind socket to interface4 and interface6 at the same time
				// and ignore the error of bind6
				_ = bindSocketToInterface6(windows.Handle(fd), ifaceIdx)
				innerErr = bindSocketToInterface4(windows.Handle(fd), ifaceIdx)
				return
			}
			switch network {
			case "tcp4", "udp4":
				innerErr = bindSocketToInterface4(windows.Handle(fd), ifaceIdx)
			case "tcp6", "udp6":
				innerErr = bindSocketToInterface6(windows.Handle(fd), ifaceIdx)
			}
		})

		if innerErr != nil {
			err = innerErr
		}

		return
	}
}

func bindSocketToInterface4(handle windows.Handle, ifaceIdx int) error {
	// MSDN says for IPv4 this needs to be in net byte order, so that it's like an IP address with leading zeros.
	// Ref: https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], uint32(ifaceIdx))
	index := *(*uint32)(unsafe.Pointer(&bytes[0]))
	err := windows.SetsockoptInt(handle, windows.IPPROTO_IP, IP_UNICAST_IF, int(index))
	if err != nil {
		return err
	}
	return nil
}

func bindSocketToInterface6(handle windows.Handle, ifaceIdx int) error {
	return windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, IPV6_UNICAST_IF, ifaceIdx)
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
