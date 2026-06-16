package tunnel

import (
	"fmt"
	"net"
	"sync"

	"github.com/igoogolx/itun2socks/internal/conn"
	"github.com/igoogolx/itun2socks/internal/dns"
	"github.com/igoogolx/itun2socks/internal/mitm"
	"github.com/igoogolx/itun2socks/internal/tunnel/statistic"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/network_iface"
	"github.com/sagernet/sing/common/bufio"
)

var (
	tcpQueue = make(chan conn.TcpConnContext, 1024)

	globalMitmMu sync.RWMutex
	globalMitm   *mitm.MitmInterceptor
)

// SetMitmInterceptor registers the MITM interceptor consulted for every port-443 TCP connection.
func SetMitmInterceptor(m *mitm.MitmInterceptor) {
	globalMitmMu.Lock()
	defer globalMitmMu.Unlock()
	globalMitm = m
}

func getMitmInterceptor() *mitm.MitmInterceptor {
	globalMitmMu.RLock()
	defer globalMitmMu.RUnlock()
	return globalMitm
}

func TcpQueue() chan conn.TcpConnContext {
	return tcpQueue
}

func handleTCPConn(ct conn.TcpConnContext) {
	metadata := ct.Metadata()

	// MITM interception hook — only for port-443 connections with a resolvable hostname.
	if metadata.DstPort.String() == "443" {
		if interceptor := getMitmInterceptor(); interceptor != nil {
			host := metadata.Host
			if host == "" {
				if cached, ok := dns.GetCachedDnsItem(metadata.DstIP.String()); ok {
					host = cached
				}
			}
			if host != "" && interceptor.ShouldIntercept(host) {
				defer ct.Wg().Done()
				dialAddr := net.JoinHostPort(host, "443")
				if err := interceptor.Intercept(ct.Conn(), dialAddr, statistic.DefaultManager, ct.Rule()); err != nil {
					log.Debugln(log.FormatLog(log.TcpPrefix, "mitm intercept %s: %v"), dialAddr, err)
				}
				return
			}
		}
	}

	remoteConn, err := conn.NewTcpConn(ct.Ctx(), metadata, ct.Rule(), network_iface.GetDefaultInterfaceName())
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

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := copyPacket(ct.Conn(), remoteConn); err != nil {
			conn.PrintPacketError(err, fmt.Sprintf(log.FormatLog(log.TcpPrefix, "fail to input: %v, remote address: %v"), err, ct.Metadata().RemoteAddress()))
		}
	}()
	go func() {
		defer wg.Done()
		if err := copyPacket(remoteConn, ct.Conn()); err != nil {
			conn.PrintPacketError(err, fmt.Sprintf(log.FormatLog(log.TcpPrefix, "fail to output: %v, remote address: %v"), err, ct.Metadata().RemoteAddress()))
		}
	}()
	wg.Wait()
}

func copyPacket(lc net.Conn, rc net.Conn) error {
	_, err := bufio.Copy(lc, rc)
	return err
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
