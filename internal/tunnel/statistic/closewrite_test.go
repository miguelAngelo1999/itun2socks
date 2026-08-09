package statistic

import (
	"net"
	"testing"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	N "github.com/sagernet/sing/common/network"
)

// halfCloseConn records whether the relay asked for a half-close or a full one.
type halfCloseConn struct {
	net.Conn
	closeWrites int
	closes      int
}

func (h *halfCloseConn) CloseWrite() error {
	h.closeWrites++
	return nil
}

func (h *halfCloseConn) Close() error {
	h.closes++
	return nil
}

// plainConn has no CloseWrite, standing in for a transport that cannot half-close.
type plainConn struct {
	net.Conn
	closes int
}

func (p *plainConn) Close() error {
	p.closes++
	return nil
}

func newTracker(t *testing.T, c net.Conn) *TcpTracker {
	t.Helper()
	m, err := newManager(16)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}
	return NewTCPTracker(c, m, &C.Metadata{}, rule_engine.Rule(nil))
}

// The relay asks for N.WriteCloser with an interface assertion and falls back to a
// full close when it is missing. A tracker embeds net.Conn, whose method set has
// no CloseWrite, so without an explicit forward the wrapper hid the capability
// and "I have finished sending" became "I have hung up" -- cutting off a response
// that was still arriving.
func TestTrackerForwardsCloseWrite(t *testing.T) {
	inner := &halfCloseConn{}
	tr := newTracker(t, inner)

	if _, ok := any(tr).(N.WriteCloser); !ok {
		t.Fatal("tracker does not satisfy N.WriteCloser; the relay will full-close instead")
	}

	if err := N.CloseWrite(tr); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	if inner.closeWrites != 1 {
		t.Errorf("CloseWrite forwarded %d times, want 1", inner.closeWrites)
	}
	if inner.closes != 0 {
		t.Errorf("a half-close closed the connection %d time(s)", inner.closes)
	}
}

// A transport that cannot half-close must not be torn down instead. Returning an
// error here would make the relay close the whole connection.
func TestTrackerCloseWriteOnPlainConnIsHarmless(t *testing.T) {
	inner := &plainConn{}
	tr := newTracker(t, inner)

	// Routed through N.CloseWrite, the way the relay does it, so this stays a
	// behavioural check rather than a compile-time one.
	if err := N.CloseWrite(tr); err != nil {
		t.Fatalf("CloseWrite on a plain conn returned %v; the relay treats that as fatal", err)
	}
	if inner.closes != 0 {
		t.Errorf("plain conn was closed %d time(s) by a half-close", inner.closes)
	}
}

// A real close must still reach the connection and stop tracking.
func TestTrackerCloseStillClosesAndLeaves(t *testing.T) {
	inner := &halfCloseConn{}
	m, err := newManager(16)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}
	tr := NewTCPTracker(inner, m, &C.Metadata{}, rule_engine.Rule(nil))

	if n := len(m.Connections()); n != 1 {
		t.Fatalf("tracked %d connections after Join, want 1", n)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if inner.closes != 1 {
		t.Errorf("underlying conn closed %d times, want 1", inner.closes)
	}
	if n := len(m.Connections()); n != 0 {
		t.Errorf("%d connections still tracked after Close", n)
	}
}
