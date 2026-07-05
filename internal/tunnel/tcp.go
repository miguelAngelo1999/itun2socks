package tunnel

import (
	"fmt"
	"net"
	"sync"

	"github.com/igoogolx/itun2socks/internal/conn"
	"github.com/igoogolx/itun2socks/internal/dns"
	"github.com/igoogolx/itun2socks/internal/mitm"
	"github.com/igoogolx/itun2socks/internal/balancer"
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
				if err := interceptor.InterceptRaw(ct.Ctx(), ct.Conn(), dialAddr, statistic.DefaultManager, ct.Rule(), network_iface.GetDefaultInterfaceName()); err != nil {
					log.Debugln(log.FormatLog(log.TcpPrefix, "mitm intercept %s: %v"), dialAddr, err)
				}
				return
			}
		}
	}

	// Load-balance all connections (PROXY + DIRECT) across interfaces.
	// Instant failover in NewTcpConn handles dead interfaces — if the dial
	// fails on the chosen NIC, it retries on the next healthy one.
	chosenIface := pickInterface()

	// Retry the CONNECT tunnel up to 2 times — the upstream proxy may have
	// dropped an idle keepalive connection. A fresh dial + CONNECT fixes it.
	var remoteConn net.Conn
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		remoteConn, err = conn.NewTcpConn(ct.Ctx(), metadata, ct.Rule(), chosenIface)
		if err == nil {
			break
		}
		if attempt < 2 {
			// "HTTP need auth" (407) or connection refused — retry with same iface
			log.Warnln(log.FormatLog(log.TcpPrefix,
				"tcp conn attempt %d failed: %v, remote: %v — retrying"),
				attempt+1, err, ct.Metadata().RemoteAddress())
		}
	}
	if chosenIface != "" {
		defer balancer.Release(chosenIface)
	}
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

func pickInterface() string {
	if iface := balancer.Pick(); iface != "" {
		log.Debugln(log.FormatLog(log.TcpPrefix, "load balance pick: %s"), iface)
		return iface
	}
	return network_iface.GetDefaultInterfaceName()
}

func pickUdpInterface() string {
	if iface := balancer.Pick(); iface != "" {
		return iface
	}
	return network_iface.GetDefaultInterfaceName()
}
