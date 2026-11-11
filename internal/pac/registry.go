package pac

import (
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/pkg/log"
)

// Registry holds a compiled PAC per proxy. Each proxy can declare its own PAC URL,
// and routing consults it after a rule has chosen that proxy but before dialing.
//
// The registry is safe for concurrent use. Hot-path reads (Eval) take an RLock;
// refreshes and updates do not hold locks during network fetches.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*entry // keyed by proxy id

	refreshStop chan struct{}
	refreshMu   sync.Mutex
}

type entry struct {
	proxyId  string
	pacUrl   string
	pacOnly  bool         // true when this proxy has no fixed server (PAC supplies the upstream)
	compiled *CompiledPAC // nil means fetch/compile failed; traffic goes through the proxy
}

// DefaultRegistry is the process-wide PAC registry, populated on manager start.
var DefaultRegistry = NewRegistry()

func NewRegistry() *Registry {
	return &Registry{
		entries: make(map[string]*entry),
	}
}

// Update synchronises the registry with the current proxy list. Proxies without
// a pacUrl are removed (no PAC = all traffic goes through the proxy). New or
// changed URLs are fetched and compiled without holding the registry lock.
func (r *Registry) Update(proxies []map[string]any, fetchProxy string) {
	type toFetch struct {
		id      string
		pacUrl  string
		pacOnly bool
	}

	var needed []toFetch
	seen := make(map[string]bool, len(proxies))

	r.mu.Lock()
	for _, p := range proxies {
		id, _ := p["id"].(string)
		pacUrl, _ := p["pacUrl"].(string)
		server, _ := p["server"].(string)
		pacOnly := server == ""
		if id == "" || pacUrl == "" {
			continue
		}
		seen[id] = true

		existing := r.entries[id]
		if existing != nil && existing.pacUrl == pacUrl {
			// URL unchanged — keep compiled PAC, but update pacOnly in case server changed
			existing.pacOnly = pacOnly
			continue
		}

		needed = append(needed, toFetch{id: id, pacUrl: pacUrl, pacOnly: pacOnly})
	}

	// Remove entries for proxies that no longer carry a PAC URL
	for id := range r.entries {
		if !seen[id] {
			delete(r.entries, id)
		}
	}
	r.mu.Unlock()

	// Fetch and compile outside lock to avoid blocking readers during network I/O
	type fetchResult struct {
		id       string
		pacUrl   string
		pacOnly  bool
		compiled *CompiledPAC
	}
	results := make([]fetchResult, 0, len(needed))
	for _, item := range needed {
		compiled := fetchAndCompile(item.pacUrl, fetchProxy)
		results = append(results, fetchResult{
			id:       item.id,
			pacUrl:   item.pacUrl,
			pacOnly:  item.pacOnly,
			compiled: compiled,
		})
	}

	// Re-lock to apply compiled entries
	r.mu.Lock()
	for _, res := range results {
		if seen[res.id] {
			r.entries[res.id] = &entry{
				proxyId:  res.id,
				pacUrl:   res.pacUrl,
				pacOnly:  res.pacOnly,
				compiled: res.compiled,
			}
			if res.compiled != nil {
				log.Infoln("[pac-registry] compiled PAC for proxy %s from %s", res.id, res.pacUrl)
			} else {
				log.Warnln("[pac-registry] failed to compile PAC for proxy %s from %s", res.id, res.pacUrl)
			}
		}
	}
	r.mu.Unlock()
}

// GetPacHosts returns unique hostnames of all registered PAC URLs.
func (r *Registry) GetPacHosts() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool)
	var hosts []string
	for _, e := range r.entries {
		if e.pacUrl == "" {
			continue
		}
		u, err := url.Parse(e.pacUrl)
		if err != nil {
			continue
		}
		h := u.Hostname()
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// GetUpstreamHosts returns unique hostnames of all upstreams declared across all compiled PACs.
func (r *Registry) GetUpstreamHosts() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool)
	var hosts []string
	for _, e := range r.entries {
		if e.compiled == nil {
			continue
		}
		for _, h := range e.compiled.ExtractUpstreamHosts() {
			if h != "" && !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	return hosts
}

// Eval evaluates the PAC for proxy [proxyId] against the given URL and host.
// Returns:
//   - ("DIRECT", true)  if the PAC says DIRECT
//   - ("PROXY", true)   if the PAC says anything else (go through the proxy)
//   - ("", false)       if this proxy has no PAC (go through the proxy)
func (r *Registry) Eval(proxyId, url, host string) (result string, hasPAC bool) {
	r.mu.RLock()
	e := r.entries[proxyId]
	r.mu.RUnlock()

	if e == nil || e.compiled == nil {
		return "", false
	}

	raw := e.compiled.Eval(url, host)
	if IsDirectResult(raw) {
		return "DIRECT", true
	}
	return "PROXY", true
}

// EvalDirective evaluates the PAC for proxy [proxyId] against the given URL and
// host and returns the RAW directive without collapsing it to DIRECT/PROXY.
func (r *Registry) EvalDirective(proxyId, url, host string) (directive string, hasPAC bool, timedOut bool) {
	r.mu.RLock()
	e := r.entries[proxyId]
	r.mu.RUnlock()

	if e == nil || e.compiled == nil {
		return "", false, false
	}

	res, to := e.compiled.EvalRaw(url, host)
	if to {
		return "", true, true
	}
	return res, true, false
}

// IsPacOnly reports whether proxy [proxyId] is a PAC-only proxy (no fixed server).
func (r *Registry) IsPacOnly(proxyId string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e := r.entries[proxyId]
	return e != nil && e.pacOnly
}

// ShouldDirect is the convenience check for the routing hook.
func (r *Registry) ShouldDirect(proxyId, host string, port string, isTLS bool) bool {
	if proxyId == "" {
		return false
	}

	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%s/", scheme, host, port)
	result, hasPAC := r.Eval(proxyId, url, host)
	return hasPAC && result == "DIRECT"
}

// StartRefreshLoop re-fetches and re-compiles all registered PACs every interval.
func (r *Registry) StartRefreshLoop(interval time.Duration, fetchProxy string) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()

	if r.refreshStop != nil {
		close(r.refreshStop)
	}
	r.refreshStop = make(chan struct{})
	stop := r.refreshStop

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.refresh(fetchProxy)
			case <-stop:
				return
			}
		}
	}()
}

// StopRefreshLoop stops the background refresh.
func (r *Registry) StopRefreshLoop() {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if r.refreshStop != nil {
		close(r.refreshStop)
		r.refreshStop = nil
	}
}

// Clear drops all entries (on disconnect).
func (r *Registry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = make(map[string]*entry)
}

func (r *Registry) refresh(fetchProxy string) {
	type refreshTarget struct {
		id      string
		pacUrl  string
		pacOnly bool
	}

	r.mu.RLock()
	targets := make([]refreshTarget, 0, len(r.entries))
	for id, e := range r.entries {
		targets = append(targets, refreshTarget{id: id, pacUrl: e.pacUrl, pacOnly: e.pacOnly})
	}
	r.mu.RUnlock()

	type refreshResult struct {
		id       string
		pacUrl   string
		pacOnly  bool
		compiled *CompiledPAC
	}
	var results []refreshResult
	for _, t := range targets {
		compiled := fetchAndCompile(t.pacUrl, fetchProxy)
		if compiled != nil {
			results = append(results, refreshResult{
				id:       t.id,
				pacUrl:   t.pacUrl,
				pacOnly:  t.pacOnly,
				compiled: compiled,
			})
		}
	}

	r.mu.Lock()
	for _, res := range results {
		if cur, ok := r.entries[res.id]; ok && cur.pacUrl == res.pacUrl {
			r.entries[res.id] = &entry{
				proxyId:  res.id,
				pacUrl:   res.pacUrl,
				pacOnly:  res.pacOnly,
				compiled: res.compiled,
			}
		}
	}
	r.mu.Unlock()
}

// fetchAndCompile downloads and compiles a PAC script. Returns nil on failure.
func fetchAndCompile(pacURL, fetchProxy string) *CompiledPAC {
	js, err := FetchViaProxy(pacURL, fetchProxy)
	if err != nil {
		log.Debugln("[pac-registry] fetch %s failed: %v", pacURL, err)
		return nil
	}
	compiled, err := Compile(js)
	if err != nil {
		log.Debugln("[pac-registry] compile %s failed: %v", pacURL, err)
		return nil
	}
	return compiled
}

// FetchViaProxy downloads a PAC script using a specific proxy (or DIRECT if empty).
func FetchViaProxy(pacURL, proxy string) (string, error) {
	return Fetch(pacURL)
}
