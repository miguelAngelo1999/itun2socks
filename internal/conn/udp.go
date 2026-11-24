package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/dns"
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
const udpReadTimeout = 60 * time.Second

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

	// Bidirectional Fake-IP (198.18.0.0/15) <-> Real-IP NAT table for relayed
	// UDP flows (e.g. WhatsApp/WebRTC STUN/DTLS/SRTP). Outbound datagrams to a
	// Fake-IP are resolved via Lux's non-Fake-IP resolver (never OS net.LookupIP,
	// which loops into Wintun's Fake-IP DNS on Windows) and cached; inbound
	// replies from the real IP are rewritten back to the Fake-IP so the app's
	// connected UDP socket accepts them.
	natMu       sync.RWMutex
	fakeToReal  map[[4]byte][4]byte
	realToFake  map[[4]byte][4]byte
	resolveIPv4 func(ctx context.Context, host string) ([]net.IP, error)
}

func isFakeIPv4(as4 [4]byte) bool {
	return as4[0] == 198 && (as4[1] == 18 || as4[1] == 19)
}

func (c *CopyablePacketConn) lookupRealForFake(fake4 [4]byte) ([4]byte, bool) {
	c.natMu.RLock()
	real4, ok := c.fakeToReal[fake4]
	c.natMu.RUnlock()
	return real4, ok
}

func (c *CopyablePacketConn) lookupFakeForReal(real4 [4]byte) ([4]byte, bool) {
	c.natMu.RLock()
	fake4, ok := c.realToFake[real4]
	c.natMu.RUnlock()
	return fake4, ok
}

func (c *CopyablePacketConn) recordNatMapping(fake4, real4 [4]byte) {
	c.natMu.Lock()
	if c.fakeToReal == nil {
		c.fakeToReal = make(map[[4]byte][4]byte)
	}
	if c.realToFake == nil {
		c.realToFake = make(map[[4]byte][4]byte)
	}
	c.fakeToReal[fake4] = real4
	c.realToFake[real4] = fake4
	c.natMu.Unlock()
}

func (c *CopyablePacketConn) resolveRealIPv4(domain string) ([4]byte, bool) {
	lookup := c.resolveIPv4
	if lookup == nil {
		lookup = dns.LookupLocalIPv4
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := lookup(ctx, domain)
	if err != nil {
		return [4]byte{}, false
	}
	for _, ip := range ips {
		if rip4 := ip.To4(); rip4 != nil {
			var as4 [4]byte
			copy(as4[:], rip4)
			if !isFakeIPv4(as4) {
				return as4, true
			}
		}
	}
	return [4]byte{}, false
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
			if isUdpConnResetError(err) {
				// Windows Winsock ICMP Port Unreachable from one peer; keep relaying
				// other peers/ICE candidates on this shared UDP socket.
				continue
			}
			return M.Socksaddr{}, err
		}
		if n == 0 {
			continue
		}
		if _, err = buffer.Write(receivedBuf[:n]); err != nil {
			return M.Socksaddr{}, fmt.Errorf("fail to write udp to buffer: %v", err)
		}
		src := M.SocksaddrFromNet(addr)
		srcAddr := src.Addr.Unmap()
		if srcAddr.Is4() {
			if fake4, ok := c.lookupFakeForReal(srcAddr.As4()); ok {
				srcAddr = netip.AddrFrom4(fake4)
			}
			// Always return a pure IPv4 Socksaddr (never ::ffff:a.b.c.d from a
			// dual-stack [::] socket). sing-tun's gVisor IPv4 UDP endpoint rejects
			// Is4In6() addresses and ends the download loop with bytes=0, err=<nil>,
			// breaking all raw-IPv4 UDP flows (e.g. WhatsApp ICE/STUN/media).
			src = M.Socksaddr{
				Addr: srcAddr,
				Port: src.Port,
			}
		}
		return src, nil
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
	dstAddr := destination.Addr.Unmap()
	if dstAddr.Is4() {
		fake4 := dstAddr.As4()
		if isFakeIPv4(fake4) {
			real4, ok := c.lookupRealForFake(fake4)
			if !ok {
				if domain, found := dns.FakeIpPool.LookBack(net.IP(fake4[:])); found && domain != "" {
					if resolved, resolvedOk := c.resolveRealIPv4(domain); resolvedOk {
						real4 = resolved
						ok = true
						c.recordNatMapping(fake4, real4)
					}
				}
			}
			if !ok {
				return fmt.Errorf("fail to resolve fake-ip udp destination %v", destination)
			}
			destination = M.Socksaddr{
				Addr: netip.AddrFrom4(real4),
				Port: destination.Port,
			}
		} else if destination.Addr.Is4In6() {
			destination = M.Socksaddr{
				Addr: dstAddr,
				Port: destination.Port,
			}
		}
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
// If the matched proxy does not support UDP, or if the flow is STUN (port 3478),
// route DIRECT via defaultInterface (physical NIC) using directDialer.
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

	if !connDialer.SupportUDP() || metadata.DstPort == 3478 {
		directDialer, err := GetProxy(constants.PolicyDirect)
		if err != nil {
			return nil, err
		}
		connDialer = directDialer
	}

	rawConn, err := connDialer.ListenPacketContext(ctx, metadata, dialer.WithInterface(defaultInterface), dialer.WithAddrReuse(true))
	if err != nil {
		return nil, err
	}
	log.Debugln(log.FormatLog(log.UdpPrefix, "relay socket %v opened for %v"), rawConn.LocalAddr(), metadata.RemoteAddress())
	return &CopyablePacketConn{PacketConn: rawConn}, nil
}
