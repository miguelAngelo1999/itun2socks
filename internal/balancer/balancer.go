// Package balancer implements per-connection load balancing across multiple
// network interfaces for DIRECT policy connections.
//
// Three strategies:
//   - "least-conn"  (default) — always pick the interface with fewest active connections.
//                               Best for mixed workloads with some long-lived connections.
//   - "round-robin"            — rotate interfaces in order regardless of load.
//                               Best for uniform short-lived connections.
//   - "failover"               — always use the first healthy interface; others are
//                               standby. Switches only when primary goes down.
//
// Works on macOS (IP_BOUND_IF), Windows (IP_UNICAST_IF), Linux (SO_BINDTODEVICE).
package balancer

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/igoogolx/itun2socks/pkg/log"
)

const healthCheckInterval = 20 * time.Second

// Strategy constants.
const (
	StrategyLeastConn  = "least-conn"
	StrategyRoundRobin = "round-robin"
	StrategyFailover   = "failover"
)

// ifaceState tracks health and active connection count for one interface.
type ifaceState struct {
	name    string
	healthy atomic.Bool
	active  atomic.Int64 // active connections (used by least-conn)
}

// Balancer holds configuration and runtime state.
type Balancer struct {
	mu       sync.RWMutex
	ifaces   []*ifaceState
	strategy string
	rrIdx    atomic.Uint64 // round-robin counter
	done     chan struct{}
}

var (
	instance *Balancer
	instMu   sync.Mutex
)

// Configure initialises the global balancer.
// strategy should be one of the Strategy* constants; defaults to StrategyLeastConn.
func Configure(ifaces []string, strategy string) {
	instMu.Lock()
	defer instMu.Unlock()

	if instance != nil {
		close(instance.done)
		instance = nil
	}
	if len(ifaces) < 2 {
		log.Infoln("[balancer] disabled (need ≥2 interfaces)")
		return
	}
	if strategy == "" {
		strategy = StrategyLeastConn
	}

	states := make([]*ifaceState, len(ifaces))
	for i, name := range ifaces {
		s := &ifaceState{name: name}
		s.healthy.Store(true)
		states[i] = s
	}

	b := &Balancer{
		ifaces:   states,
		strategy: strategy,
		done:     make(chan struct{}),
	}
	instance = b
	log.Infoln("[balancer] enabled — strategy=%s interfaces=%v", strategy, ifaces)
	go b.healthLoop()
}

// Pick selects the next interface according to the configured strategy.
// Increments the active counter (decremented by Release when the conn closes).
// Returns "" if balancing is disabled.
func Pick() string {
	instMu.Lock()
	b := instance
	instMu.Unlock()
	if b == nil {
		return ""
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	switch b.strategy {
	case StrategyRoundRobin:
		return b.pickRoundRobin()
	case StrategyFailover:
		return b.pickFailover()
	default: // least-conn
		return b.pickLeastConn()
	}
}

// Release decrements the active counter when a connection closes.
func Release(ifaceName string) {
	instMu.Lock()
	b := instance
	instMu.Unlock()
	if b == nil || ifaceName == "" {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.ifaces {
		if s.name == ifaceName && s.active.Load() > 0 {
			s.active.Add(-1)
			return
		}
	}
}

// IsEnabled reports whether balancing is active.
func IsEnabled() bool {
	instMu.Lock()
	defer instMu.Unlock()
	return instance != nil
}

// GetStatus returns interface names, healthy subset, next pick, strategy, and enabled.
func GetStatus() (interfaces []string, healthy []string, nextIface string, strategy string, enabled bool) {
	instMu.Lock()
	b := instance
	instMu.Unlock()
	if b == nil {
		return nil, nil, "", "", false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	all := make([]string, 0, len(b.ifaces))
	hlth := make([]string, 0, len(b.ifaces))
	for _, s := range b.ifaces {
		all = append(all, s.name)
		if s.healthy.Load() {
			hlth = append(hlth, s.name)
		}
	}

	// Compute next without mutating state
	next := b.peekNext()
	return all, hlth, next, b.strategy, true
}

// ── Strategy implementations ──────────────────────────────────────────────

func (b *Balancer) pickLeastConn() string {
	var best *ifaceState
	for _, s := range b.ifaces {
		if !s.healthy.Load() {
			continue
		}
		if best == nil || s.active.Load() < best.active.Load() {
			best = s
		}
	}
	return b.acquire(best)
}

func (b *Balancer) pickRoundRobin() string {
	healthy := b.healthyList()
	if len(healthy) == 0 {
		return b.fallback()
	}
	idx := b.rrIdx.Add(1) - 1
	chosen := healthy[idx%uint64(len(healthy))]
	chosen.active.Add(1)
	return chosen.name
}

func (b *Balancer) pickFailover() string {
	// Always use first healthy interface (primary)
	for _, s := range b.ifaces {
		if s.healthy.Load() {
			s.active.Add(1)
			return s.name
		}
	}
	return b.fallback()
}

func (b *Balancer) peekNext() string {
	switch b.strategy {
	case StrategyRoundRobin:
		h := b.healthyList()
		if len(h) == 0 {
			return b.fallback()
		}
		idx := b.rrIdx.Load()
		return h[idx%uint64(len(h))].name
	case StrategyFailover:
		for _, s := range b.ifaces {
			if s.healthy.Load() {
				return s.name
			}
		}
		return b.fallback()
	default: // least-conn
		var best *ifaceState
		for _, s := range b.ifaces {
			if !s.healthy.Load() {
				continue
			}
			if best == nil || s.active.Load() < best.active.Load() {
				best = s
			}
		}
		if best != nil {
			return best.name
		}
		return b.fallback()
	}
}

func (b *Balancer) acquire(s *ifaceState) string {
	if s == nil {
		return b.fallback()
	}
	s.active.Add(1)
	return s.name
}

func (b *Balancer) fallback() string {
	if len(b.ifaces) > 0 {
		return b.ifaces[0].name
	}
	return ""
}

func (b *Balancer) healthyList() []*ifaceState {
	out := make([]*ifaceState, 0, len(b.ifaces))
	for _, s := range b.ifaces {
		if s.healthy.Load() {
			out = append(out, s)
		}
	}
	return out
}

// ── Health checking ───────────────────────────────────────────────────────

func (b *Balancer) healthLoop() {
	b.checkAll()
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-b.done:
			return
		case <-ticker.C:
			b.checkAll()
		}
	}
}

func (b *Balancer) checkAll() {
	b.mu.RLock()
	ifaces := b.ifaces
	b.mu.RUnlock()
	for _, s := range ifaces {
		h := checkInterface(s.name)
		s.healthy.Store(h)
		if !h {
			log.Debugln("[balancer] %s: unhealthy", s.name)
		}
	}
}

// checkInterface returns true if the interface is Up with a routable IPv4.
func checkInterface(ifaceName string) bool {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return false
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}
