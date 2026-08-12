package net

import (
	"context"
	"net"

	"github.com/sagernet/sing/common/bufio"
)

// Relay copies between left and right bidirectionally, propagating half-close.
//
// The previous implementation used two io.Copy goroutines with
// SetReadDeadline(time.Now()) as the shutdown signal when one direction ended.
// That doesn't propagate a FIN to the remote peer — the peer never learns the
// other side has finished, so keep-alive connections sit in FIN_WAIT_2 forever.
// Streaming responses (Kiro, SSE, chunked APIs) stall because the client's
// half-close never reaches the server, so the server never sends its own FIN.
//
// CopyConn calls CloseWrite on the peer when a direction reaches EOF, which is
// the correct TCP half-close. Both sides learn the other has finished, and
// connections are cleaned up.
func Relay(leftConn, rightConn net.Conn) {
	_ = bufio.CopyConn(context.Background(), leftConn, rightConn)
}
