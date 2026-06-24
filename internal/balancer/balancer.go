// Package balancer implements per-connection round-robin load balancing
// across multiple network interfaces for DIRECT policy connections.
//
// Each new DIRECT TCP/UDP connection is assigned the next healthy interface
// in rotation. If an interface loses connectivity (health check fails),
// it's temporarily removed from rotation until it recovers.
//
// Works on macOS (IP_BOUND_IF), Windows (IP_UNICAST_IF), and Linux (SO_BINDTODEVICE)
// via the existing platform-specific bind code in pkg/clash/component/dialer.
package balancer

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/igoogolx/itun2socks/pkg/log"
)

const (
	healthCheckInterval = 20 * time.Second
	healthCheckTimeout  = 3 * time.Second
	// Use DNS (8.8.8.8:53) — works even behind corporate proxies and firewalls
	healthCheckTarget = "8.8.8.8:53"
)

// Balancer distributes DIRECT connections across healthy interfaces in round-robin order.
type Balancer struct {
	mu         sync.RWMutex
	interfaces []string // all configured interfaces
	healthy    []string // currently healthy subset (preserves original order)
	counter    uint64
	cancel     context.CancelFunc
}

var (
	instance *Balancer
	instMu   sync.Mutex
)

// Configure sets up the global balancer with the given interfaces.
// Pass nil or empty to disable load balancing (uses default interface only).
// Safe to call multiple times — previous balancer is stopped.
func Configure(ifaces []string) {
	instMu.Lock()
	defer instMu.Unlock()

	// Stop existing balancer
	if instance != nil {
		instance.stop()
		instance = nil
	}

	if len(ifaces) < 2 {
		// Need at least 2 interfaces to balance
		log.Infoln("[balancer] disabled (fewer than 2 interfaces)")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	b := &Balancer{
		interfaces: append([]string{}, ifaces...), // defensive copy
		healthy:    append([]string{}, ifaces...), // assume all healthy initially
		cancel:     cancel,
	}
	instance = b
	log.Infoln("[balancer] enabled with interfaces: %v", ifaces)
	go b.healthLoop(ctx)
}

// Pick returns the next interface to use for a DIRECT connection.
// Returns "" if load balancing is disabled (caller should use default interface).
func Pick() string {
	instMu.Lock()
	b := instance
	instMu.Unlock()

	if b == nil {
		return ""
	}
	return b.pick()
}

// IsEnabled reports whether load balancing is currently active.
func IsEnabled() bool {
	instMu.Lock()
	defer instMu.Unlock()
	return instance != nil
}

// GetStatus returns the current interfaces and their health status.
func GetStatus() (interfaces []string, healthy []string, nextIface string, enabled bool) {
	instMu.Lock()
	b := instance
	instMu.Unlock()

	if b == nil {
		return nil, nil, "", false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	next := ""
	if len(b.healthy) > 0 {
		idx := atomic.LoadUint64(&b.counter)
		next = b.healthy[idx%uint64(len(b.healthy))]
	}
	return append([]string{}, b.interfaces...), append([]string{}, b.healthy...), next, true
}

func (b *Balancer) pick() string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.healthy) == 0 {
		// All unhealthy — fall back to first configured
		if len(b.interfaces) > 0 {
			return b.interfaces[0]
		}
		return ""
	}
	idx := atomic.AddUint64(&b.counter, 1) - 1
	return b.healthy[idx%uint64(len(b.healthy))]
}

func (b *Balancer) stop() {
	if b.cancel != nil {
		b.cancel()
	}
}

func (b *Balancer) healthLoop(ctx context.Context) {
	b.checkAll()
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.checkAll()
		}
	}
}

func (b *Balancer) checkAll() {
	type result struct {
		iface   string
		healthy bool
	}
	ch := make(chan result, len(b.interfaces))
	for _, name := range b.interfaces {
		go func(n string) {
			ch <- result{n, checkInterface(n)}
		}(name)
	}

	healthySet := make(map[string]bool)
	for range b.interfaces {
		r := <-ch
		healthySet[r.iface] = r.healthy
		if !r.healthy {
			log.Debugln("[balancer] %s: unhealthy (removed from rotation)", r.iface)
		}
	}

	// Preserve original order
	ordered := make([]string, 0, len(b.interfaces))
	for _, name := range b.interfaces {
		if healthySet[name] {
			ordered = append(ordered, name)
		}
	}

	b.mu.Lock()
	b.healthy = ordered
	b.mu.Unlock()

	log.Debugln("[balancer] healthy: %v (%d/%d)", ordered, len(ordered), len(b.interfaces))
}

// checkInterface tests whether the named interface is up and has a routable
// IPv4 address. We don't attempt a TCP dial because in TUN/mixed mode all
// outbound traffic is captured by the TUN stack regardless of LocalAddr binding,
// making external health checks unreliable. Interface presence + address is
// sufficient — the OS routing table handles actual packet delivery.
func checkInterface(ifaceName string) bool {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return false
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
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
