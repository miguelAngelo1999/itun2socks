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
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/igoogolx/itun2socks/pkg/log"
)

const (
	healthCheckInterval = 5 * time.Second
	latencyTarget       = "8.8.8.8:53"
	latencyTimeout      = 2 * time.Second
)

// Strategy constants.
const (
	StrategyLeastConn  = "least-conn"
	StrategyRoundRobin = "round-robin"
	StrategyFailover   = "failover"
	StrategyWeighted   = "weighted" // proportional to measured latency (faster = more load)
)

// ifaceState tracks health, active connection count, and latency for one interface.
type ifaceState struct {
	name      string
	healthy   atomic.Bool
	active    atomic.Int64 // active connections (least-conn)
	latencyMs atomic.Int64 // measured RTT in ms (weighted); 0 = not yet measured
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
	case StrategyWeighted:
		return b.pickWeighted()
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

// MarkUnhealthy immediately marks an interface as unhealthy (used for instant failover).
// Also flushes all active connections so stale sockets on the dead interface are dropped.
func MarkUnhealthy(ifaceName string) {
	instMu.Lock()
	b := instance
	instMu.Unlock()
	if b == nil || ifaceName == "" {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.ifaces {
		if s.name == ifaceName {
			wasHealthy := s.healthy.Swap(false)
			if wasHealthy {
				log.Warnln("[balancer] %s marked unhealthy — flushing connections", ifaceName)
				// Trigger connection flush via the route change handler
				// This ensures all existing connections on the dead interface get dropped
				if onFlush != nil {
					go onFlush()
				}
			}
			return
		}
	}
}

// onFlush is called when an interface becomes unhealthy to flush stale connections.
var onFlush func()

// SetFlushHandler registers a callback to flush connections when failover triggers.
func SetFlushHandler(fn func()) {
	onFlush = fn
}

// IsEnabled reports whether balancing is active.
func IsEnabled() bool {
	instMu.Lock()
	defer instMu.Unlock()
	return instance != nil
}

// GetStatus returns interface names, healthy subset, next pick, strategy, latencies, and enabled.
func GetStatus() (interfaces []string, healthy []string, nextIface string, strategy string, latencies map[string]int64, enabled bool) {
	instMu.Lock()
	b := instance
	instMu.Unlock()
	if b == nil {
		return nil, nil, "", "", nil, false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	all := make([]string, 0, len(b.ifaces))
	hlth := make([]string, 0, len(b.ifaces))
	lats := make(map[string]int64)
	for _, s := range b.ifaces {
		all = append(all, s.name)
		if s.healthy.Load() {
			hlth = append(hlth, s.name)
		}
		lat := s.latencyMs.Load()
		if lat > 0 {
			lats[s.name] = lat
		}
	}
	next := b.peekNext()
	return all, hlth, next, b.strategy, lats, true
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

// pickWeighted selects proportionally to inverse latency:
// lower latency → more connections. Uses weighted random selection.
// Falls back to least-conn if no latency data yet.
func (b *Balancer) pickWeighted() string {
	healthy := b.healthyList()
	if len(healthy) == 0 {
		return b.fallback()
	}
	// Build weights: weight = 1000 / latencyMs (lower latency = higher weight)
	// If latency not measured yet, use weight=1 for all (equal distribution)
	weights := make([]int64, len(healthy))
	hasData := false
	for i, s := range healthy {
		lat := s.latencyMs.Load()
		if lat > 0 {
			weights[i] = 1000 / lat
			if weights[i] < 1 {
				weights[i] = 1
			}
			hasData = true
		} else {
			weights[i] = 1
		}
	}
	if !hasData {
		// No latency data yet — fall back to least-conn
		return b.pickLeastConn()
	}
	// Weighted selection using counter mod total weight
	total := int64(0)
	for _, w := range weights {
		total += w
	}
	idx := b.rrIdx.Add(1) - 1
	pos := int64(idx) % total
	cum := int64(0)
	for i, w := range weights {
		cum += w
		if pos < cum {
			healthy[i].active.Add(1)
			return healthy[i].name
		}
	}
	// Fallback
	healthy[0].active.Add(1)
	return healthy[0].name
}

func (b *Balancer) peekWeighted() string {
	healthy := b.healthyList()
	if len(healthy) == 0 {
		return b.fallback()
	}
	// Show the interface with highest weight (lowest latency)
	var best *ifaceState
	for _, s := range healthy {
		lat := s.latencyMs.Load()
		if lat == 0 {
			continue
		}
		if best == nil || lat < best.latencyMs.Load() {
			best = s
		}
	}
	if best != nil {
		return best.name
	}
	return healthy[0].name
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
	case StrategyWeighted:
		return b.peekWeighted()
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
		if !h && isInterfacePhysicallyPresent(s.name) {
			// Interface is physically present (Up+Running) but has no IPv4.
			// Attempt automatic recovery: bounce the interface + renew DHCP.
			log.Infoln("[balancer] %s: up but no IPv4 — attempting DHCP recovery", s.name)
			recoverInterface(s.name)
			// Re-check after recovery attempt
			h = checkInterface(s.name)
		}
		if h {
			// Measure latency for weighted strategy
			ms := measureLatency(s.name)
			if ms > 0 {
				s.latencyMs.Store(ms)
			}
		}
		wasHealthy := s.healthy.Swap(h)
		if !h && wasHealthy {
			log.Warnln("[balancer] %s: became unhealthy", s.name)
			if onFlush != nil {
				go onFlush()
			}
		} else if h && !wasHealthy {
			log.Infoln("[balancer] %s: recovered — back in rotation", s.name)
		}
	}
}

// measureLatency measures TCP connect RTT to latencyTarget bound to ifaceName.
// Returns milliseconds, or 0 on failure.
// Note: in TUN/mixed mode this may not work (traffic captured by TUN).
// That's acceptable — weighted strategy degrades to least-conn if no data.
func measureLatency(ifaceName string) int64 {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return 0
	}
	addrs, _ := iface.Addrs()
	var localIP net.IP
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			localIP = ip
			break
		}
	}
	if localIP == nil {
		return 0
	}
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: localIP, Port: 0},
		Timeout:   latencyTimeout,
	}
	start := time.Now()
	conn, err := d.Dial("tcp4", latencyTarget)
	if err != nil {
		return 0
	}
	ms := time.Since(start).Milliseconds()
	conn.Close()
	if ms < 1 {
		ms = 1
	}
	return ms
}

// isInterfacePhysicallyPresent checks if the interface is Up+Running (cable connected)
// but just lacks an IP address (DHCP failed).
func isInterfacePhysicallyPresent(ifaceName string) bool {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return false
	}
	// Must be Up AND Running flags
	if iface.Flags&net.FlagUp == 0 ||
		iface.Flags&net.FlagRunning == 0 ||
		iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	// On macOS, also check ifconfig output for "status: active" — the kernel
	// flags can show UP|RUNNING even when the physical link is down (inactive).
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("ifconfig", ifaceName).Output()
		if err != nil {
			return true // assume present if we can't check
		}
		// If status is explicitly "inactive", no physical link — don't attempt recovery
		if strings.Contains(string(out), "status: inactive") {
			return false
		}
	}
	return true
}

// recoverInterface attempts to bounce the interface and renew DHCP.
// This handles the case where a USB ethernet adapter loses its DHCP lease
// but is still physically connected (Up+Running, no IPv4).
func recoverInterface(ifaceName string) {
	if runtime.GOOS != "darwin" {
		return
	}
	// ifconfig down/up + DHCP renewal
	_ = exec.Command("sudo", "-n", "ifconfig", ifaceName, "down").Run()
	time.Sleep(1 * time.Second)
	_ = exec.Command("sudo", "-n", "ifconfig", ifaceName, "up").Run()
	time.Sleep(2 * time.Second)
	_ = exec.Command("sudo", "-n", "ipconfig", "set", ifaceName, "DHCP").Run()
	time.Sleep(3 * time.Second) // give DHCP time to assign
	log.Infoln("[balancer] %s: DHCP recovery attempt completed", ifaceName)
}

// ExtractRawName extracts the OS interface name from a friendly-format string.
// Flutter stores interfaces as "Friendly Name (en0)" — we need "en0".
func ExtractRawName(name string) string {
	start := len(name) - 1
	for start >= 0 && name[start] != '(' {
		start--
	}
	end := len(name) - 1
	for end >= 0 && name[end] != ')' {
		end--
	}
	if start >= 0 && end > start {
		return strings.TrimSpace(name[start+1 : end])
	}
	return strings.TrimSpace(name)
}
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
