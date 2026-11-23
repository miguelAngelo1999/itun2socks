package executor

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// defaultStunProbeTargets are well-known public STUN servers (IPv4 literals so
// probing never depends on DNS or hits Fake-IP).
//   - 162.159.207.0:3478  (stun.cloudflare.com — port 3478, same as WhatsApp STUN)
//   - 74.125.250.129:19302 (stun.l.google.com)
var defaultStunProbeTargets = []string{
	"162.159.207.0:3478",
	"74.125.250.129:19302",
}

const stunMagicCookie uint32 = 0x2112A442

// buildStunBindingRequest constructs a minimal 20-byte RFC 5389 STUN Binding Request.
func buildStunBindingRequest(txID [12]byte) []byte {
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(pkt[2:4], 0x0000) // Message Length = 0
	binary.BigEndian.PutUint32(pkt[4:8], stunMagicCookie)
	copy(pkt[8:20], txID[:])
	return pkt
}

// isValidStunResponse verifies a STUN Binding Success Response with matching magic cookie & txID.
func isValidStunResponse(resp []byte, txID [12]byte) bool {
	if len(resp) < 20 {
		return false
	}
	msgType := binary.BigEndian.Uint16(resp[0:2])
	cookie := binary.BigEndian.Uint32(resp[4:8])
	if msgType != 0x0101 || cookie != stunMagicCookie {
		return false
	}
	for i := 0; i < 12; i++ {
		if resp[8+i] != txID[i] {
			return false
		}
	}
	return true
}

// probeDirectUDP tests whether non-DNS outbound UDP reaches public STUN servers
// directly via defaultInterface within timeout. Returns true if at least one
// STUN server replies with a valid Binding Response.
func probeDirectUDP(ctx context.Context, defaultInterface string, targets []string, timeout time.Duration) bool {
	if len(targets) == 0 {
		return true
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var opts []dialer.Option
	if defaultInterface != "" {
		opts = append(opts, dialer.WithInterface(defaultInterface))
	}

	resultCh := make(chan bool, len(targets))
	var wg sync.WaitGroup
	for idx, target := range targets {
		wg.Add(1)
		go func(i int, addrStr string) {
			defer wg.Done()
			raddr, err := net.ResolveUDPAddr("udp4", addrStr)
			if err != nil {
				resultCh <- false
				return
			}
			pc, err := dialer.ListenPacket(probeCtx, "udp4", ":0", opts...)
			if err != nil {
				resultCh <- false
				return
			}
			defer pc.Close()

			deadline, ok := probeCtx.Deadline()
			if !ok {
				deadline = time.Now().Add(timeout)
			}
			_ = pc.SetDeadline(deadline)

			var txID [12]byte
			binary.BigEndian.PutUint64(txID[0:8], uint64(time.Now().UnixNano()))
			txID[8] = byte(i)
			txID[9] = 0x4c // 'L'
			txID[10] = 0x55 // 'U'
			txID[11] = 0x58 // 'X'

			req := buildStunBindingRequest(txID)
			if _, err := pc.WriteTo(req, raddr); err != nil {
				resultCh <- false
				return
			}
			buf := make([]byte, 512)
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				resultCh <- false
				return
			}
			resultCh <- isValidStunResponse(buf[:n], txID)
		}(idx, target)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for ok := range resultCh {
		if ok {
			cancel()
			return true
		}
	}
	return false
}

// probeAndConfigureUdpBlock runs asynchronously after TUN starts when the
// selected upstream proxy lacks UDP support (e.g. HTTP Squid). If direct
// outbound UDP works on the physical NIC, we leave direct UDP relay enabled;
// if direct UDP is firewalled, we activate the dynamic WFP UDP block on Windows
// so VoIP apps (WhatsApp/Zoom) fast-fail UDP and fall back to TURN-over-TCP.
func probeAndConfigureUdpBlock(ctx context.Context, defaultInterface string) {
	reachable := probeDirectUDP(ctx, defaultInterface, defaultStunProbeTargets, 1500*time.Millisecond)
	if ctx.Err() != nil {
		return
	}
	if reachable {
		log.Infoln(log.FormatLog(log.ExecutorPrefix, "[UDP-PROBE] direct UDP reachable via %s — keeping direct UDP relay enabled"), defaultInterface)
		return
	}
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "[UDP-PROBE] direct UDP blocked on %s — activating WFP fast-fail UDP block for TURN-over-TCP fallback"), defaultInterface)
	if err := ApplyUdpBlock(); err != nil {
		log.Warnln(log.FormatLog(log.ExecutorPrefix, "[UDP-PROBE] ApplyUdpBlock failed: %v"), err)
	}
}
