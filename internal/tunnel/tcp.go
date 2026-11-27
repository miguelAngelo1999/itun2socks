package tunnel

import (
	"errors"
	"fmt"
	"net"
	"time"

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
	dialStart := time.Now()
	target := conn.FormatTargetForLog(ct.Metadata())
	procTag := conn.FormatProcessTag(ct.Metadata())
	policy := ct.Rule().GetPolicy()
	policyLabel := conn.ResolvePolicyLabel(policy)

	remoteConn, err := conn.NewTcpConn(ct.Ctx(), ct.Metadata(), ct.Rule(), network_iface.GetDefaultInterfaceName())
	defer func() {
		ct.Wg().Done()
		if err := closeConn(ct.Conn()); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Debugln(log.FormatLog(log.TcpPrefix, "fail to close local tcp conn,err: %v"), err)
		}
		if err := closeConn(remoteConn); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Debugln(log.FormatLog(log.TcpPrefix, "fail to close remote tcp conn, err: %v"), err)
		}
	}()
	if err != nil {
		if tag, denied := ClassifyProxyError(err); denied {
			log.Warnln(log.FormatLog(log.TcpPrefix, "[DENY] [PROXY_DENIED] [%s] %s%s via %s — %v"), tag, target, procTag, policyLabel, err)
		} else {
			log.Warnln(log.FormatLog(log.TcpPrefix, "[DIAL_FAIL] %s%s via %s — %v"), target, procTag, policyLabel, err)
		}
		return
	}
	tracker := statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, ct.Metadata(), ct.Rule())
	remoteConn = tracker

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
	relayErr := bufio.CopyConn(ct.Ctx(), ct.Conn(), remoteConn)
	upBytes := tracker.UploadTotal.Load()
	downBytes := tracker.DownloadTotal.Load()
	if isEarlyUpstreamReset(policy, upBytes, downBytes, time.Since(dialStart), relayErr) {
		if relayErr != nil {
			log.Warnln(log.FormatLog(log.TcpPrefix, "[PROXY_RESET] %s%s via %s — upstream closed/reset right after handshake (possible SNI/TLS block, ↑%dB ↓%dB): %v"), target, procTag, policyLabel, upBytes, downBytes, relayErr)
		} else {
			log.Warnln(log.FormatLog(log.TcpPrefix, "[PROXY_RESET] %s%s via %s — upstream closed right after handshake with no reply (possible SNI/TLS block, ↑%dB ↓%dB)"), target, procTag, policyLabel, upBytes, downBytes)
		}
	} else if relayErr != nil {
		conn.PrintPacketError(relayErr, fmt.Sprintf(log.FormatLog(log.TcpPrefix, "relay ended: %v, remote address: %v"), relayErr, target))
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
