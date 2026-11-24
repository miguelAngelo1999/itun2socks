package conn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/igoogolx/itun2socks/internal/dns"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyablePacketConn_FakeIPBidirectionalNAT(t *testing.T) {
	// Echo UDP server on 127.0.0.1 simulating a real STUN/media peer.
	echoServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer echoServer.Close()

	serverPort := echoServer.LocalAddr().(*net.UDPAddr).Port

	go func() {
		b := make([]byte, 512)
		for {
			n, raddr, err := echoServer.ReadFromUDP(b)
			if err != nil {
				return
			}
			_, _ = echoServer.WriteToUDP(b[:n], raddr)
		}
	}()

	// Allocate a Fake-IP for a WhatsApp STUN host.
	fakeIP := dns.FakeIpPool.Lookup("stun-test.whatsapp.net")
	require.NotNil(t, fakeIP)
	fake4 := fakeIP.To4()
	require.NotNil(t, fake4)

	clientRaw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer clientRaw.Close()

	resolveCalls := 0
	cpc := &CopyablePacketConn{
		PacketConn: clientRaw,
		resolveIPv4: func(ctx context.Context, host string) ([]net.IP, error) {
			resolveCalls++
			// Return a Fake-IP first to verify it is skipped in favor of the real IP.
			return []net.IP{net.IPv4(198, 18, 0, 99), net.IPv4(127, 0, 0, 1)}, nil
		},
	}

	dest := M.SocksaddrFromNet(&net.UDPAddr{IP: fake4, Port: serverPort})
	outBuf := buf.NewPacket()
	defer outBuf.Release()
	_, err = outBuf.Write([]byte("stun-ping"))
	require.NoError(t, err)

	// Outbound write to Fake-IP should resolve via resolveIPv4 -> 127.0.0.1 and succeed.
	require.NoError(t, cpc.WritePacket(outBuf, dest))
	assert.Equal(t, 1, resolveCalls)

	// Second write to the same Fake-IP should hit the NAT cache (no extra DNS lookup).
	outBuf2 := buf.NewPacket()
	defer outBuf2.Release()
	_, _ = outBuf2.Write([]byte("stun-ping-2"))
	require.NoError(t, cpc.WritePacket(outBuf2, dest))
	assert.Equal(t, 1, resolveCalls)

	// Inbound reply from 127.0.0.1 MUST be rewritten back to fakeIP:serverPort!
	inBuf := buf.NewPacket()
	defer inBuf.Release()
	src, err := cpc.ReadPacket(inBuf)
	require.NoError(t, err)
	assert.Equal(t, fake4.String(), src.Addr.String())
	assert.True(t, src.Addr.Is4())
	assert.False(t, src.Addr.Is4In6())
	assert.Equal(t, uint16(serverPort), src.Port)
	assert.Equal(t, "stun-ping", string(inBuf.Bytes()))
}

type fakeDualStackPacketConn struct {
	net.PacketConn
	readPayload []byte
	readAddr    net.Addr
	writtenAddr net.Addr
}

func (f *fakeDualStackPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n := copy(p, f.readPayload)
	return n, f.readAddr, nil
}

func (f *fakeDualStackPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.writtenAddr = addr
	return len(p), nil
}

func (f *fakeDualStackPacketConn) SetReadDeadline(_ time.Time) error { return nil }

func TestCopyablePacketConn_RawIPv4Unmaps4In6FromDualStackSocket(t *testing.T) {
	// Simulate Windows dual-stack [::] UDP socket returning IPv4-mapped IPv6
	// ::ffff:162.159.207.0:3478 (raw IPv4 STUN / WhatsApp ICE relay, NOT Fake-IP).
	mappedIP := net.ParseIP("::ffff:162.159.207.0")
	require.NotNil(t, mappedIP)
	raw := &fakeDualStackPacketConn{
		readPayload: []byte("stun-reply"),
		readAddr:    &net.UDPAddr{IP: mappedIP, Port: 3478},
	}

	cpc := &CopyablePacketConn{PacketConn: raw}

	// Outbound write to raw IPv4 literal works without NAT lookup.
	outBuf := buf.NewPacket()
	defer outBuf.Release()
	_, err := outBuf.Write([]byte("stun-req"))
	require.NoError(t, err)
	require.NoError(t, cpc.WritePacket(outBuf, M.ParseSocksaddr("162.159.207.0:3478")))
	require.NotNil(t, raw.writtenAddr)
	assert.Equal(t, "162.159.207.0:3478", raw.writtenAddr.String())

	// Inbound ReadPacket MUST return a pure IPv4 netip.Addr (Is4 && !Is4In6),
	// otherwise sing-tun's gVisor IPv4 UDP endpoint drops it immediately with
	// bytes=0, err=<nil>.
	inBuf := buf.NewPacket()
	defer inBuf.Release()
	src, err := cpc.ReadPacket(inBuf)
	require.NoError(t, err)
	assert.True(t, src.Addr.Is4(), "expected pure IPv4 addr, got %v (is4In6=%v)", src.Addr, src.Addr.Is4In6())
	assert.False(t, src.Addr.Is4In6(), "must not return IPv4-mapped IPv6 addr: %v", src.Addr)
	assert.Equal(t, "162.159.207.0", src.Addr.String())
	assert.Equal(t, uint16(3478), src.Port)
	assert.Equal(t, "stun-reply", string(inBuf.Bytes()))
}
