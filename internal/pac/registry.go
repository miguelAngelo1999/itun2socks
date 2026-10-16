package pac

import (
	"fmt"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/pkg/log"
)

// Registry holds a compiled PAC per proxy. Each proxy can declare its own PAC URL,
// and routing consults it after a rule has chosen that proxy but before dialing.
//
// This replaces the former global singleton, which was consulted in the clash
// match() fallback and broke streaming traffic by re-proxying already-proxied
// connections.
//
// The registry is safe for concurrent use. Hot-path reads (Eval) take an RLock;
// refreshes take a full Lock but run in a background goroutine at 30min intervals.
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
// changed URLs are fetched and compiled. Unchanged entries keep their compiled
// state to avoid re-fetching on every config read.
//
// fetchProxy is the proxy to use when fetching PAC scripts. It must NOT be the
// proxy the PAC belongs to (chicken-and-egg). Pass "" for DIRECT or a preproxy
// address like "http://127.0.0.1:8079".
func (r *Registry) Update(proxies []map[string]any, fetchProxy string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	seen := make(map[string]bool, len(proxies))
	for _, p := range proxies {
		id, _ := p["id"].(string)
		url, _ := p["pacUrl"].(string)
		server, _ := p["server"].(string)
		pacOnly := server == ""
		if id == "" || url == "" {
			continue
		}
		seen[id] = true

		existing := r.entries[id]
		if existing != nil && existing.pacUrl == url {
			// URL unchanged — keep the compiled version, but refresh the
			// pacOnly flag in case the server field changed.
			existing.pacOnly = pacOnly
			continue
		}

		// New or changed: fetch and compile.
		compiled := fetchAndCompile(url, fetchProxy)
		r.entries[id] = &entry{proxyId: id, pacUrl: url, pacOnly: pacOnly, compiled: compiled}
		if compiled != nil {
			log.Infoln("[pac-registry] compiled PAC for proxy %s from %s", id, url)
		} else {
			log.Warnln("[pac-registry] failed to compile PAC for proxy %s from %s", id, url)
		}
	}

	// Remove entries for proxies that no longer carry a PAC URL.
	for id := range r.entries {
		if !seen[id] {
			delete(r.entries, id)
		}
	}
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
//
// Unlike Eval, this preserves the upstream address the PAC chose, e.g.
// "PROXY 10.0.0.1:8080" or "SOCKS5 10.0.0.1:1080". This is what a PAC-only
// (dynamic) outbound needs so it can dial the exact upstream the PAC selected
// per connection.
//
// Returns:
//   - (directive, true, false)  the raw directive string if this proxy has a compiled PAC
//   - ("", false, false)        if this proxy has no PAC
//   - ("", true, true)          if the PAC evaluation timed out (caller should fail, not DIRECT)
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

// IsPacOnly reports whether proxy [proxyId] is a PAC-only proxy (no fixed
// server; the PAC supplies the upstream per connection). The dial-time
// ShouldDirect gate is skipped for these so the dynamic outbound is the single
// PAC-eval authority — it honors per-connection DIRECT and fails (never leaks
// DIRECT) on eval timeout.
func (r *Registry) IsPacOnly(proxyId string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e := r.entries[proxyId]
	return e != nil && e.pacOnly
}

// ShouldDirect is the convenience check for the routing hook: does proxy P's PAC
// say this host should go DIRECT?
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
// Call this once after Update on manager start.
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
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, e := range r.entries {
		compiled := fetchAndCompile(e.pacUrl, fetchProxy)
		if compiled != nil {
			r.entries[id] = &entry{proxyId: id, pacUrl: e.pacUrl, pacOnly: e.pacOnly, compiled: compiled}
		}
		// On failure, keep the old compiled version rather than clearing it.
	}
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
// This must NOT use the proxy the PAC belongs to.
func FetchViaProxy(pacURL, proxy string) (string, error) {
	// Reuse the existing Fetch which uses http.DefaultClient. If a proxy is
	// specified, we temporarily set the env and use a custom transport.
	// For now, use the existing Fetch — it works via the preproxy at 8079
	// because the caller sets http_proxy before starting the core.
	return Fetch(pacURL)
}
