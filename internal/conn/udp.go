package conn

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/pool"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

// udpReadTimeout bounds how long a relayed UDP flow waits for an inbound packet
// before it is torn down. Media flows (STUN/RTP) send continuously, so an idle
// gap this long means the flow is really over.
const udpReadTimeout = 30 * time.Second

type UdpConnContext struct {
	ctx      context.Context
	metadata *C.Metadata
	conn     network.PacketConn
	rule     rule_engine.Rule
	wg       *sync.WaitGroup
}

func (u *UdpConnContext) Wg() *sync.WaitGroup {
	return u.wg
}

func (u *UdpConnContext) Ctx() context.Context {
	return u.ctx
}

func (u *UdpConnContext) Rule() rule_engine.Rule {
	return u.rule
}

func (u *UdpConnContext) Metadata() *C.Metadata {
	return u.metadata
}

func (u *UdpConnContext) Conn() network.PacketConn {
	return u.conn
}

func NewUdpConnContext(ctx context.Context, conn network.PacketConn, metadata *C.Metadata, wg *sync.WaitGroup) (*UdpConnContext, error) {

	rule := handleMetadata(metadata)

	var connContext = &UdpConnContext{
		ctx,
		metadata,
		conn,
		rule,
		wg,
	}

	return connContext, nil
}

type CopyablePacketConn struct {
	net.PacketConn
}

func shouldIgnorePacketError(err error) bool {
	// ignore simple error
	if E.IsTimeout(err) || E.IsClosed(err) || E.IsCanceled(err) {
		return true
	}
	return false
}

func PrintPacketError(err error, msg string) {
	printLog := log.Warnln
	if shouldIgnorePacketError(err) {
		printLog = log.Debugln
	}
	printLog(msg)
}

// ReadPacket reads exactly one datagram and reports the address it came from.
//
// The previous implementation looped after a successful read instead of
// returning, so it could only ever exit via the read deadline. Every inbound
// datagram was therefore held until the deadline fired and then handed to the
// caller with a nil source address, which the copy loop turned into a write to
// an invalid destination. DNS never hit this because it has its own handler;
// only relayed non-DNS UDP (voice/video media) came through here.
func (c *CopyablePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	receivedBuf := pool.NewBytes(pool.BufSize)
	defer pool.FreeBytes(receivedBuf)
	for {
		if err := c.SetReadDeadline(time.Now().Add(udpReadTimeout)); err != nil {
			return M.Socksaddr{}, fmt.Errorf("fail to set udp conn read deadline: %v", err)
		}
		n, addr, err := c.ReadFrom(receivedBuf)
		if err != nil {
			return M.Socksaddr{}, err
		}
		if n == 0 {
			continue
		}
		if _, err = buffer.Write(receivedBuf[:n]); err != nil {
			return M.Socksaddr{}, fmt.Errorf("fail to write udp to buffer: %v", err)
		}
		return M.SocksaddrFromNet(addr), nil
	}
}

// WritePacket sends one datagram to destination.
//
// net.PacketConn ends up at *net.UDPConn, whose WriteTo type-asserts the address
// to *net.UDPAddr. Passing an M.Socksaddr straight through fails that assertion
// with EINVAL and the datagram is lost, so convert it here.
func (c *CopyablePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.IsValid() {
		return fmt.Errorf("fail to write udp: invalid destination %v", destination)
	}
	_, err := c.WriteTo(buffer.Bytes(), destination.UDPAddr())
	return err
}

type CopyableReaderWriterConn struct {
	network.PacketConn
}

func (uc *CopyableReaderWriterConn) ReadFrom(data []byte) (int, net.Addr, error) {

	var err error
	var dest M.Socksaddr

	buff := buf.NewPacket()

	defer buff.Release()
	dest, err = uc.ReadPacket(buff)

	if err != nil {
		return 0, nil, err
	}

	n, err := buff.Read(data)

	if err != nil {
		return 0, nil, err
	}

	return n, dest, nil
}

func (uc *CopyableReaderWriterConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	newBuf := buf.NewPacket()
	defer newBuf.Release()
	_, err := newBuf.Write(data)
	if err != nil {
		return 0, err
	}
	err = uc.WritePacket(newBuf, M.SocksaddrFromNet(addr))
	return len(data), err
}

// NewUdpConn builds the outbound packet conn for a UDP flow.
//
// HTTP/HTTPS proxies are TCP-only. Handing them a UDP flow fails with
// "no support", and dropping the flow instead black-holes it inside the TUN:
// the route for the destination still points at the TUN device, so retransmits
// are swallowed too and nothing reaches the wire.
//
// When the matched policy resolves to a proxy that cannot carry UDP, relay the
// flow DIRECT out the physical interface instead. TCP still goes through the
// proxy; UDP goes straight out, which is what system-proxy mode does.
//
// One socket per flow is correct here: sing keys its UDP NAT sessions on the
// client source address alone, so all destinations reached from a single client
// port share one session and therefore one outbound socket. That keeps the
// public mapping consistent across ICE candidates.
func NewUdpConn(ctx context.Context, metadata *C.Metadata, rule rule_engine.Rule, defaultInterface string) (*CopyablePacketConn, error) {
	policy := rule.GetPolicy()
	connDialer, err := GetProxy(policy)
	if err != nil {
		return nil, err
	}

	if policy != constants.PolicyDirect && !connDialer.SupportUDP() {
		directDialer, dErr := GetProxy(constants.PolicyDirect)
		if dErr != nil {
			return nil, fmt.Errorf("proxy %v cannot carry udp and direct dialer is unavailable: %v", policy, dErr)
		}
		log.Infoln(log.FormatLog(log.UdpPrefix, "proxy cannot carry udp, relaying DIRECT: %v -> %v"),
			metadata.SourceAddress(), metadata.RemoteAddress())
		connDialer = directDialer
	}

	rawConn, err := connDialer.ListenPacketContext(ctx, metadata, dialer.WithInterface(defaultInterface), dialer.WithAddrReuse(true))
	if err != nil {
		return nil, err
	}
	log.Debugln(log.FormatLog(log.UdpPrefix, "relay socket %v opened for %v"), rawConn.LocalAddr(), metadata.RemoteAddress())
	return &CopyablePacketConn{rawConn}, nil
}
