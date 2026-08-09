package tunnel

import (
	"fmt"

	"github.com/igoogolx/itun2socks/internal/conn"
	"github.com/igoogolx/itun2socks/internal/tunnel/statistic"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/network_iface"
	"github.com/sagernet/sing/common/bufio"
)

var (
	tcpQueue = make(chan conn.TcpConnContext, 1024)
)

func TcpQueue() chan conn.TcpConnContext {
	return tcpQueue
}

func handleTCPConn(ct conn.TcpConnContext) {
	remoteConn, err := conn.NewTcpConn(ct.Ctx(), ct.Metadata(), ct.Rule(), network_iface.GetDefaultInterfaceName())
	defer func() {
		ct.Wg().Done()
		if err := closeConn(ct.Conn()); err != nil {
			log.Debugln(log.FormatLog(log.TcpPrefix, "fail to close local tcp conn,err: %v"), err)
		}
		if err := closeConn(remoteConn); err != nil {
			log.Debugln(log.FormatLog(log.TcpPrefix, "fail to close remote tcp conn, err: %v"), err)
		}
	}()
	if err != nil {
		log.Warnln(log.FormatLog(log.TcpPrefix, "fail to get tcp conn, err: %v, rule: %v, remote address: %v"), err, ct.Rule().GetPolicy(), ct.Metadata().RemoteAddress())
		return
	}
	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, ct.Metadata(), ct.Rule())

	// CopyConn, rather than two bufio.Copy goroutines joined by a WaitGroup.
	//
	// The WaitGroup version required *both* directions to finish before the
	// deferred close ran, and it never propagated a half-close. For a streaming
	// response that means:
	//
	//  1. the client sends its request and goes quiet, so the client -> server
	//     copy blocks on a read that will not return while the client holds its
	//     end open
	//  2. the server finishes the response and sends FIN, so the server ->
	//     client copy returns
	//  3. Wait() is still blocked on step 1, so nothing is closed and that FIN is
	//     never passed on to the client
	//
	// The client sits waiting for the end of a body it has already received in
	// full, which is what a long-lived streaming request looks like when it
	// hangs. The connection, its two goroutines and both file descriptors also
	// leak for as long as the client keeps its side open.
	//
	// CopyConn calls CloseWrite on the peer when a direction reaches EOF, so each
	// side learns the other has finished, and closes outright on error.
	if err := bufio.CopyConn(ct.Ctx(), ct.Conn(), remoteConn); err != nil {
		conn.PrintPacketError(err, fmt.Sprintf(log.FormatLog(log.TcpPrefix, "relay ended: %v, remote address: %v"), err, ct.Metadata().RemoteAddress()))
	}
}

func processTCP() {
	for c := range tcpQueue {
		go handleTCPConn(c)
	}
}

type CloseableConn interface {
	Close() error
}

func closeConn(conn CloseableConn) error {
	if conn != nil {
		return conn.Close()
	}
	return nil
}
