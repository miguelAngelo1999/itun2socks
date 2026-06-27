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

func (c *CopyablePacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	receivedBuf := pool.NewBytes(pool.BufSize)
	defer pool.FreeBytes(receivedBuf)
	for {
		err := c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			return M.Socksaddr{}, fmt.Errorf("fail to set udp conn read deadline: %v", err)
		}
		n, addr, err := c.ReadFrom(receivedBuf)
		if shouldIgnorePacketError(err) {
			return M.SocksaddrFromNet(addr), nil
		}
		if err != nil {
			return M.Socksaddr{}, fmt.Errorf("fail to read udp from copyable conn:%v", err)
		}
		_, err = buffer.Write(receivedBuf[:n])
		if err != nil {
			return M.Socksaddr{}, fmt.Errorf("fail to write udp to bufffer:%v", err)
		}
	}
}

func (c *CopyablePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	_, err := c.WriteTo(buffer.Bytes(), destination)
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

func NewUdpConn(ctx context.Context, metadata *C.Metadata, rule rule_engine.Rule, defaultInterface string) (*CopyablePacketConn, error) {
	connDialer, err := GetProxy(rule.GetPolicy())
	if err != nil {
		return nil, err
	}

	// If the selected proxy doesn't support UDP (e.g. HTTP proxy), fall back to DIRECT
	// immediately rather than waiting for a write failure ("invalid argument").
	if !connDialer.SupportUDP() && rule.GetPolicy() != constants.PolicyDirect {
		directDialer, dErr := GetProxy(constants.PolicyDirect)
		if dErr == nil {
			rawConn, dErr2 := directDialer.ListenPacketContext(ctx, metadata,
				dialer.WithInterface(defaultInterface),
				dialer.WithAddrReuse(true),
				dialer.WithFallbackBind(true))
			if dErr2 == nil {
				return &CopyablePacketConn{rawConn}, nil
			}
		}
	}

	rawConn, err := connDialer.ListenPacketContext(ctx, metadata, dialer.WithInterface(defaultInterface), dialer.WithAddrReuse(true))
	if err != nil {
		// If the proxy doesn't support UDP (e.g. HTTP proxy), fall back to DIRECT.
		if err.Error() == "no support" && rule.GetPolicy() != constants.PolicyDirect {
			directDialer, dErr := GetProxy(constants.PolicyDirect)
			if dErr == nil {
				rawConn, err = directDialer.ListenPacketContext(ctx, metadata,
					dialer.WithInterface(defaultInterface),
					dialer.WithAddrReuse(true),
					dialer.WithFallbackBind(true))
				if err == nil {
					return &CopyablePacketConn{rawConn}, nil
				}
			}
		}
		return nil, err
	}
	return &CopyablePacketConn{rawConn}, nil
}
