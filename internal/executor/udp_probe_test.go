package executor

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbeDirectUDP_ReachableAndBlocked(t *testing.T) {
	// Mock local STUN server replying with valid RFC 5389 Binding Success Response.
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer srv.Close()

	go func() {
		b := make([]byte, 512)
		for {
			n, raddr, err := srv.ReadFromUDP(b)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			resp := make([]byte, 20)
			binary.BigEndian.PutUint16(resp[0:2], 0x0101) // Binding Success Response
			binary.BigEndian.PutUint16(resp[2:4], 0x0000)
			binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
			copy(resp[8:20], b[8:20])
			_, _ = srv.WriteToUDP(resp, raddr)
		}
	}()

	assert.True(t, probeDirectUDP(context.Background(), "", []string{srv.LocalAddr().String()}, 500*time.Millisecond))

	// Silent UDP sink (never replies) simulates firewalled outbound UDP.
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer sink.Close()

	assert.False(t, probeDirectUDP(context.Background(), "", []string{sink.LocalAddr().String()}, 150*time.Millisecond))
}
