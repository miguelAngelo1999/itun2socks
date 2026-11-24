//go:build windows

package conn

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isUdpConnResetError detects Winsock's WSAECONNRESET (10054) returned on an
// unconnected UDP socket when a single remote ICE/STUN peer replies with ICMP
// Port Unreachable. Ignoring it prevents one closed peer from tearing down the
// shared outbound UDP relay socket for all other ICE candidates.
func isUdpConnResetError(err error) bool {
	return errors.Is(err, windows.WSAECONNRESET)
}
