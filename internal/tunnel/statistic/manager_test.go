package statistic

import (
	"fmt"
	"testing"

	"go.uber.org/atomic"
)

// fakeTracker records how many times Close was called and whether it left the
// manager, so a test can tell a bookkeeping removal from an actual teardown.
type fakeTracker struct {
	id      string
	closes  *atomic.Int32
	manager *Manager
}

func (f *fakeTracker) ID() string { return f.id }

// Mirrors TcpTracker.Close: leave the manager, then close the connection.
func (f *fakeTracker) Close() error {
	f.closes.Inc()
	if f.manager != nil {
		f.manager.Leave(f)
	}
	return nil
}

func newFake(m *Manager, id string) *fakeTracker {
	return &fakeTracker{id: id, closes: atomic.NewInt32(0), manager: m}
}

// Overflowing the cache must not close the connection it stops tracking.
//
// A streaming response only refreshes its LRU position when bytes move, so an
// idle stream reaches the tail and used to be closed mid-response by the
// eviction callback. The request then hangs with nothing logged as an error.
func TestOverflowDoesNotCloseEvictedConnection(t *testing.T) {
	m, err := newManager(4)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}

	idle := newFake(m, "idle-stream")
	m.Join(idle)

	// Push it out of the cache with unrelated traffic.
	for i := 0; i < 8; i++ {
		m.Join(newFake(m, fmt.Sprintf("noise-%d", i)))
	}

	if got := idle.closes.Load(); got != 0 {
		t.Fatalf("evicted connection was closed %d time(s); eviction must only stop tracking", got)
	}

	// It is no longer listed, which is the only thing eviction should change.
	for _, c := range m.Connections() {
		if c.ID() == idle.ID() {
			t.Fatal("evicted connection is still tracked")
		}
	}
}

// Leave goes through Cache.Remove, and golang-lru fires the eviction callback on
// Remove as well as on overflow. When that callback closed the value, every
// ordinary teardown closed the socket twice.
func TestLeaveDoesNotReenterClose(t *testing.T) {
	m, err := newManager(16)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}

	tr := newFake(m, "normal")
	m.Join(tr)

	if err := tr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if got := tr.closes.Load(); got != 1 {
		t.Fatalf("Close ran %d times, want 1 (eviction callback is re-entering)", got)
	}
	if len(m.Connections()) != 0 {
		t.Fatalf("tracker still listed after close")
	}
}

// The cap has to be large enough that ordinary desktop use does not reach it.
func TestTrackedConnectionCapIsNotTiny(t *testing.T) {
	if maxTrackedConnections < 1024 {
		t.Fatalf("maxTrackedConnections = %d; a busy machine exceeds this routinely",
			maxTrackedConnections)
	}
}

// CloseAllConnections must still terminate everything and leave nothing behind.
func TestCloseAllConnections(t *testing.T) {
	m, err := newManager(16)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}

	trackers := make([]*fakeTracker, 5)
	for i := range trackers {
		trackers[i] = newFake(m, fmt.Sprintf("c-%d", i))
		m.Join(trackers[i])
	}

	m.CloseAllConnections()

	for i, tr := range trackers {
		if got := tr.closes.Load(); got != 1 {
			t.Errorf("tracker %d closed %d times, want 1", i, got)
		}
	}
	if n := len(m.Connections()); n != 0 {
		t.Errorf("%d connections still tracked after CloseAllConnections", n)
	}
}
