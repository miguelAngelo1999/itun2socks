package pac

import (
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/igoogolx/itun2socks/pkg/log"
)

// Manager holds the currently active PAC state.
//
// Two execution modes coexist:
//   - JS eval mode: a CompiledPAC is stored in activeCompiled. EvalForURL()
//     evaluates FindProxyForURL() per-connection. Active when a PAC URL is
//     configured (user-set or DHCP) and the JS compiled successfully.
//   - Regex rules mode: activeRules holds pre-parsed DIRECT rules extracted
//     by the regex parser. Active only as the legacy fallback path.
//
// At most one mode is active at a time. Clear() disables both.
var (
	// JS eval mode
	activeCompiled unsafe.Pointer // *CompiledPAC, accessed via atomic

	// Regex rules mode (legacy fallback)
	activeRules []Rule
	activeMu    sync.RWMutex

	// User-configured PAC URL (from settings). Takes priority over DHCP/registry.
	userURLMu sync.RWMutex
	userURL   string

	// Currently applied PAC URL (either user-configured or auto-detected).
	activePacURL string

	// Refresh loop control
	refreshStop chan struct{}
	refreshMu   sync.Mutex
)

// ── Compiled PAC accessors (atomic, lock-free on hot path) ───────────────────

func getActiveCompiled() *CompiledPAC {
	p := atomic.LoadPointer(&activeCompiled)
	if p == nil {
		return nil
	}
	return (*CompiledPAC)(p)
}

func setActiveCompiled(c *CompiledPAC) {
	if c == nil {
		atomic.StorePointer(&activeCompiled, nil)
	} else {
		atomic.StorePointer(&activeCompiled, unsafe.Pointer(c))
	}
}

// IsJSEvalActive reports whether JS per-connection eval is currently active.
func IsJSEvalActive() bool {
	return getActiveCompiled() != nil
}

// ── User URL (from settings) ──────────────────────────────────────────────────

// SetUserURL stores the user-configured PAC URL from settings.
// Call this on startup (after reading config.json) and on every PUT /setting.
// An empty string disables user-configured PAC (auto-detect takes over).
func SetUserURL(url string) {
	userURLMu.Lock()
	defer userURLMu.Unlock()
	userURL = url
}

// GetUserURL returns the user-configured PAC URL.
func GetUserURL() string {
	userURLMu.RLock()
	defer userURLMu.RUnlock()
	return userURL
}

// ── Active PAC URL (whichever URL is currently applied) ──────────────────────

// GetPacURL returns the URL of the currently applied PAC (user or auto-detected).
func GetPacURL() string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activePacURL
}

// ── Apply / Clear ─────────────────────────────────────────────────────────────

// Apply fetches the PAC at url, compiles it for JS eval, and also runs the
// regex parser to populate activeRules as a fallback.
// On success the JS compiled PAC is stored atomically and becomes the active
// evaluator. On parse failure the compiled PAC is cleared (regex rules remain).
func Apply(url string) ([]Rule, error) {
	if url == "" {
		Clear()
		return nil, nil
	}

	js, err := Fetch(url)
	if err != nil {
		log.Warnln("[pac] failed to fetch PAC from %s: %v", url, err)
		return nil, err
	}

	// Try to compile the PAC script for JS evaluation.
	compiled, compileErr := Compile(js)
	if compileErr != nil {
		log.Warnln("[pac] failed to compile PAC from %s: %v — using regex fallback", url, compileErr)
	}

	// Also run the regex parser to populate rules (used by the regex path
	// and by /pac/status for display).
	rules, parseErr := Parse(js)
	if parseErr != nil {
		log.Warnln("[pac] regex parse error for %s: %v", url, parseErr)
	}

	activeMu.Lock()
	activeRules = rules
	activePacURL = url
	activeMu.Unlock()

	if compileErr == nil {
		setActiveCompiled(compiled)
		log.Infoln("[pac] JS eval active — FindProxyForURL compiled from %s (%d regex rules also parsed)", url, len(rules))
	} else {
		setActiveCompiled(nil)
		log.Infoln("[pac] regex fallback active — %d rules from %s", len(rules), url)
	}

	RefreshMyIP()
	return rules, nil
}

// Clear removes all active PAC state and disables both eval modes.
// Called on TUN disconnect and when the user clears the PAC URL.
func Clear() {
	setActiveCompiled(nil)
	activeMu.Lock()
	activeRules = nil
	activePacURL = ""
	activeMu.Unlock()
	// Invalidate DNS and myIP caches so next Apply starts fresh.
	if c := getDNSCache(); c != nil {
		c.Purge()
	}
	log.Infoln("[pac] cleared active PAC state")
}

// ── Rule accessors (legacy / display) ────────────────────────────────────────

// GetActiveRules returns the currently parsed PAC rules (regex path).
func GetActiveRules() []Rule {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return append([]Rule{}, activeRules...)
}

// GetDirectDomains returns DIRECT domain-suffix rules as plain strings.
func GetDirectDomains() []string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	var domains []string
	for _, r := range activeRules {
		if r.Policy == "DIRECT" && (r.Type == "DOMAIN-SUFFIX" || r.Type == "DOMAIN") {
			domains = append(domains, r.Payload)
		}
	}
	return domains
}

// GetDirectCIDRs returns DIRECT IP-CIDR rules as plain strings.
func GetDirectCIDRs() []string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	var cidrs []string
	for _, r := range activeRules {
		if r.Policy == "DIRECT" && r.Type == "IP-CIDR" {
			cidrs = append(cidrs, r.Payload)
		}
	}
	return cidrs
}

// ── Refresh loop ──────────────────────────────────────────────────────────────

// StartRefreshLoop begins a background goroutine that re-applies the current
// PAC URL every interval. Call from TunClient.Start().
func StartRefreshLoop(interval time.Duration) {
	refreshMu.Lock()
	defer refreshMu.Unlock()
	if refreshStop != nil {
		return // already running
	}
	stop := make(chan struct{})
	refreshStop = stop
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				url := GetUserURL()
				if url == "" {
					url = GetPacURL() // re-apply whatever was auto-detected
				}
				if url == "" {
					continue
				}
				if _, err := Apply(url); err != nil {
					log.Warnln("[pac] refresh failed for %s: %v — keeping previous state", url, err)
				} else {
					log.Debugln("[pac] refreshed PAC from %s", url)
				}
			case <-stop:
				return
			}
		}
	}()
	log.Infoln("[pac] refresh loop started (interval: %v)", interval)
}

// StopRefreshLoop stops the background refresh goroutine. Call from TunClient.Close().
func StopRefreshLoop() {
	refreshMu.Lock()
	defer refreshMu.Unlock()
	if refreshStop != nil {
		close(refreshStop)
		refreshStop = nil
		log.Infoln("[pac] refresh loop stopped")
	}
}
