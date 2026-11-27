package routes

// net_switch.go — auto-proxy switching & captive-portal assist controller + HTTP API.
//
// States: IDLE, PROBING, CORPORATE(proxyID), DIRECT, CAPTIVE_PORTAL, NO_INTERNET
//
// Concurrency model:
//   - c.mu protects controller fields (short critical sections; never held across
//     network probes or manager.Start/Close).
//   - c.transitionMu serializes ALL routing/manager transitions (SetEnabled,
//     NotifyManualSelect, ManualStart, ManualStop, runCycle apply, enterCaptivePortal,
//     exitCaptivePortal, recovery ticker apply) so manual actions and background
//     probes can never interleave or flap TUN.
//   - c.epoch is bumped on every external user/config mutation; in-flight probe
//     cycles re-verify c.epoch under transitionMu before applying any change.
//   - c.captiveGen uniquely identifies each captive_portal episode; stale
//     captive exits abort cleanly under transitionMu without closing a newer session.

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/conn"
	"github.com/igoogolx/itun2socks/internal/dns"
	"github.com/igoogolx/itun2socks/internal/executor"
	"github.com/igoogolx/itun2socks/internal/manager"
	"github.com/igoogolx/itun2socks/internal/matcher"
	"github.com/igoogolx/itun2socks/internal/tunnel/statistic"
	"github.com/igoogolx/itun2socks/pkg/clash/adapter"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// ── State machine ────────────────────────────────────────────────────────────

type switchState string

const (
	stateIdle          switchState = "idle"
	stateProbing       switchState = "probing"
	stateCorporate     switchState = "corporate"
	stateDirect        switchState = "direct"
	stateCaptivePortal switchState = "captive_portal"
	stateNoInternet    switchState = "no_internet"
)

const (
	defaultPreferredBackInterval = 45 * time.Second
	defaultCaptivePollInterval   = 4 * time.Second
	defaultCaptiveMaxDuration    = 3 * time.Minute
	defaultCaptiveCooldown       = 2 * time.Minute
	maxTriggerReasonLen          = 64
)

type SwitchStatus struct {
	Enabled          bool        `json:"enabled"`
	State            switchState `json:"state"`
	ActiveProxyID    string      `json:"activeProxyId"`   // proxy ID or "direct"
	ActiveProxyName  string      `json:"activeProxyName"` // human-readable
	CaptivePortalURL string      `json:"captivePortalUrl,omitempty"`
	LastSwitchedAt   time.Time   `json:"lastSwitchedAt"`
	LastReason       string      `json:"lastReason"`
	LastTriggeredAt  time.Time   `json:"lastTriggeredAt"`
	Probing          bool        `json:"probing"`
}

var switchCtrl = &switchController{}

type switchController struct {
	// transitionMu serializes all manager/routing mutations. Always acquire
	// transitionMu BEFORE mu when both are needed.
	transitionMu sync.Mutex
	mu           sync.Mutex

	enabled          bool
	state            switchState
	activeProxyID    string
	activeProxyName  string
	captivePortalURL string
	directOverride   bool
	lastSwitchedAt   time.Time
	lastReason       string
	lastTriggeredAt  time.Time
	probing          bool
	rerunPending     bool
	pendingReason    string

	// epoch increments on every user/config mutation (SetEnabled, NotifyManual*)
	// so in-flight probes abort cleanly rather than applying stale decisions.
	epoch uint64

	// lastUserProxyID is the proxy the user manually selected last.
	// Auto-switch never overwrites this — it's used to restore routing
	// and as the starting point after boot or captive-portal resume.
	lastUserProxyID   string
	lastUserProxyName string
	manualHoldUntil   time.Time // suppress auto-switch (proxy/direct) for 10 min after manual select

	// Saved proxy to resume fail-closed after exiting stateCaptivePortal.
	captiveResumeProxyID   string
	captiveResumeProxyName string

	// Cooldown after a captive-portal safety timeout prevents infinite
	// pause/resume loops on hostile or abandoned captive networks.
	captiveCooldownUntil time.Time

	// preferredBackTicker polls every 45s while in DIRECT or NO_INTERNET to
	// detect when a configured proxy (or network) is back.
	preferredBackTicker *time.Ticker
	stopChan            chan struct{}

	// Captive-portal fast polling loop + hard safety cap.
	captiveGen      uint64
	captiveStopChan chan struct{}
	captiveWakeChan chan struct{}

	// Injectable timings & dependencies for deterministic unit tests.
	// Zero/nil values fall back to production defaults.
	preferredBackInterval time.Duration
	captivePollInterval   time.Duration
	captiveMaxDuration    time.Duration
	captiveCooldown       time.Duration

	probeProxiesFn       func([]ProxyCandidate) []ProbeResult
	probeDirectFn        func() DirectProbeResult
	getProxiesFn         func() ([]map[string]any, error)
	getProxyPasswordFn   func(string) string
	getSelectedProxyIDFn func() string
	isManagerStartedFn   func() bool
	startManagerFn       func() error
	closeManagerFn       func() error
	applyDirectModeFn    func() error
	applyCorporateModeFn func(proxyID string, closeExisting bool) error
	broadcastFn          func(payload map[string]any)
}

// ── Dependency accessors ─────────────────────────────────────────────────────

func (c *switchController) getPreferredBackInterval() time.Duration {
	if c.preferredBackInterval > 0 {
		return c.preferredBackInterval
	}
	return defaultPreferredBackInterval
}

func (c *switchController) getCaptivePollInterval() time.Duration {
	if c.captivePollInterval > 0 {
		return c.captivePollInterval
	}
	return defaultCaptivePollInterval
}

func (c *switchController) getCaptiveMaxDuration() time.Duration {
	if c.captiveMaxDuration > 0 {
		return c.captiveMaxDuration
	}
	return defaultCaptiveMaxDuration
}

func (c *switchController) getCaptiveCooldown() time.Duration {
	if c.captiveCooldown > 0 {
		return c.captiveCooldown
	}
	return defaultCaptiveCooldown
}

func (c *switchController) probeProxies(candidates []ProxyCandidate) []ProbeResult {
	if c.probeProxiesFn != nil {
		return c.probeProxiesFn(candidates)
	}
	return probeProxiesParallel(candidates)
}

func (c *switchController) probeDirect() DirectProbeResult {
	if c.probeDirectFn != nil {
		return c.probeDirectFn()
	}
	return probeDirect()
}

func (c *switchController) getProxies() ([]map[string]any, error) {
	if c.getProxiesFn != nil {
		return c.getProxiesFn()
	}
	return configuration.GetProxies()
}

func (c *switchController) getProxyPassword(id string) string {
	if c.getProxyPasswordFn != nil {
		return c.getProxyPasswordFn(id)
	}
	return getProxyPassword(id)
}

func (c *switchController) getSelectedProxyID() string {
	if c.getSelectedProxyIDFn != nil {
		return c.getSelectedProxyIDFn()
	}
	data, err := configuration.Read()
	if err != nil {
		return ""
	}
	return data.Selected.Proxy
}

func (c *switchController) isManagerStarted() bool {
	if c.isManagerStartedFn != nil {
		return c.isManagerStartedFn()
	}
	return manager.GetIsStarted()
}

func (c *switchController) startManager() error {
	if c.startManagerFn != nil {
		return c.startManagerFn()
	}
	return manager.Start()
}

func (c *switchController) closeManager() error {
	if c.closeManagerFn != nil {
		return c.closeManagerFn()
	}
	return manager.Close()
}

func (c *switchController) applyDirectMode() error {
	if c.applyDirectModeFn != nil {
		return c.applyDirectModeFn()
	}
	return defaultApplyDirectMode()
}

func (c *switchController) applyCorporateMode(proxyID string, closeExisting bool) error {
	if c.applyCorporateModeFn != nil {
		return c.applyCorporateModeFn(proxyID, closeExisting)
	}
	return defaultApplyCorporateMode(proxyID, closeExisting)
}

func (c *switchController) broadcast(payload map[string]any) {
	if c.broadcastFn != nil {
		c.broadcastFn(payload)
		return
	}
	BroadcastEvent("net_switch", payload)
}

// ── Public API ───────────────────────────────────────────────────────────────

// NotifyManualSelect records a user proxy selection, sets a 10-min hold on
// automatic proxy/direct switching, updates any pending captive-portal resume
// target, and exits any active in-memory direct override fail-closed.
func (c *switchController) NotifyManualSelect(proxyID, proxyName string) {
	c.transitionMu.Lock()
	defer c.transitionMu.Unlock()

	c.mu.Lock()
	c.epoch++
	c.lastUserProxyID = proxyID
	c.lastUserProxyName = proxyName
	c.manualHoldUntil = time.Now().Add(10 * time.Minute)
	if c.state == stateCaptivePortal {
		// If the user selects a proxy while paused for captive portal, ensure
		// exitCaptivePortal resumes onto their newly chosen proxy.
		c.captiveResumeProxyID = proxyID
		c.captiveResumeProxyName = proxyName
		holdUntil := c.manualHoldUntil
		c.mu.Unlock()
		log.Infoln("[net-switch] manual select during captive_portal: %s (%s) — hold until %s",
			proxyName, proxyID, holdUntil.Format(time.TimeOnly))
		return
	}
	wasDirect := c.directOverride
	holdUntil := c.manualHoldUntil
	c.mu.Unlock()

	if wasDirect {
		if err := c.applyCorporateMode(proxyID, true); err != nil {
			log.Errorln("[net-switch] restore after manual select failed (%v) — failing closed", err)
			c.failClosedLocked("manual select restore failed", err)
			return
		}
	}

	c.mu.Lock()
	c.directOverride = false
	c.activeProxyID = proxyID
	c.activeProxyName = proxyName
	c.state = stateCorporate
	c.stopPreferredBackTickerLocked()
	c.mu.Unlock()

	log.Infoln("[net-switch] manual select: %s (%s) — hold until %s",
		proxyName, proxyID, holdUntil.Format(time.TimeOnly))
}

// ManualStop atomically cancels any active captive-portal auto-resume loop and
// recovery ticker, then closes the manager under transitionMu so a background
// captive resume can never race and restart TUN after manual STOP.
func (c *switchController) ManualStop() error {
	c.transitionMu.Lock()
	defer c.transitionMu.Unlock()

	c.notifyManualStopUnderTransitionLock()
	return c.closeManager()
}

// NotifyManualStop cancels captive-portal auto-resume and recovery loops.
// Used directly by tests or callers that manage manager.Close separately.
func (c *switchController) NotifyManualStop() {
	c.transitionMu.Lock()
	defer c.transitionMu.Unlock()
	c.notifyManualStopUnderTransitionLock()
}

func (c *switchController) notifyManualStopUnderTransitionLock() {
	c.mu.Lock()
	wasCaptive := c.state == stateCaptivePortal
	c.epoch++
	c.captiveGen++
	c.stopCaptiveLoopLocked()
	c.stopPreferredBackTickerLocked()
	c.directOverride = false
	c.captivePortalURL = ""
	c.activeProxyID = ""
	c.activeProxyName = ""
	c.rerunPending = false
	c.state = stateIdle
	c.mu.Unlock()

	if wasCaptive {
		log.Infoln("[net-switch] manual stop cleared active captive_portal pause")
	}
}

// ManualStart atomically cancels any captive-portal loop/ticker and starts the
// manager under transitionMu so background transitions cannot interleave.
func (c *switchController) ManualStart() error {
	c.transitionMu.Lock()
	defer c.transitionMu.Unlock()

	c.notifyManualStartUnderTransitionLock()
	return c.startManager()
}

// NotifyManualStart cancels active captive-portal / recovery loops and clears
// directOverride + safety cooldown.
func (c *switchController) NotifyManualStart() {
	c.transitionMu.Lock()
	defer c.transitionMu.Unlock()
	c.notifyManualStartUnderTransitionLock()
}

func (c *switchController) notifyManualStartUnderTransitionLock() {
	c.mu.Lock()
	c.epoch++
	c.captiveGen++
	c.stopCaptiveLoopLocked()
	c.stopPreferredBackTickerLocked()
	c.directOverride = false
	c.captivePortalURL = ""
	c.captiveCooldownUntil = time.Time{}
	if c.state == stateCaptivePortal || c.state == stateDirect || c.state == stateNoInternet {
		c.state = stateCorporate
	}
	c.mu.Unlock()
}

// Trigger runs a probe cycle. Safe to call concurrently — a trigger arriving
// while a cycle is already running coalesces into one follow-up rerun instead
// of being dropped (so a mid-probe network change is never lost).
//
// Runs even when autoSwitchEnabled == false (as long as Lux is running or
// currently paused in stateCaptivePortal) so captive-portal sign-in assist
// works automatically while direct fallback remains opt-in.
func (c *switchController) Trigger(reason string) {
	reason = sanitizeReason(reason)
	if reason == "" {
		// Default to "auto" (NOT "manual") so unnamed internal triggers still
		// respect the 10-min manual-select hold.
		reason = "auto"
	}

	c.mu.Lock()
	if reason == "manual" {
		// Explicit user trigger clears any captive-portal safety cooldown.
		c.captiveCooldownUntil = time.Time{}
	}
	if c.state == stateCaptivePortal {
		if c.captiveWakeChan != nil {
			select {
			case c.captiveWakeChan <- struct{}{}:
			default:
			}
		}
		c.lastTriggeredAt = time.Now()
		c.mu.Unlock()
		return
	}
	if c.probing {
		c.rerunPending = true
		// Preserve "manual" precedence if either trigger was explicit.
		if c.pendingReason != "manual" {
			c.pendingReason = reason
		}
		c.mu.Unlock()
		return
	}
	enabled := c.enabled
	c.mu.Unlock()

	// Do not start probe churn when Lux is manually stopped.
	if !c.isManagerStarted() {
		if !enabled {
			return
		}
		return
	}

	c.mu.Lock()
	if c.state == stateCaptivePortal {
		c.mu.Unlock()
		return
	}
	if c.probing {
		c.rerunPending = true
		if c.pendingReason != "manual" {
			c.pendingReason = reason
		}
		c.mu.Unlock()
		return
	}
	c.probing = true
	c.lastTriggeredAt = time.Now()
	c.mu.Unlock()

	go c.runCycleLoop(reason)
}

func (c *switchController) runCycleLoop(initialReason string) {
	reason := initialReason
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errorln("[net-switch] panic recovered in runCycle(%s): %v", reason, r)
				}
			}()
			c.runCycle(reason)
		}()

		c.mu.Lock()
		if !c.rerunPending || c.state == stateCaptivePortal {
			c.rerunPending = false
			c.pendingReason = ""
			c.probing = false
			c.mu.Unlock()
			return
		}
		reason = c.pendingReason
		c.rerunPending = false
		c.pendingReason = ""
		c.mu.Unlock()
	}
}

// SetEnabled turns opt-in auto-switch (alternate proxy + direct fallback) on or
// off. Disabling restores corporate routing atomically (failing closed if
// restore errors) without disturbing an active captive-portal sign-in assist.
func (c *switchController) SetEnabled(enabled bool) {
	c.transitionMu.Lock()
	defer c.transitionMu.Unlock()

	c.mu.Lock()
	c.epoch++
	c.enabled = enabled
	wasDirect := false
	restoreID := ""
	restoreName := ""
	if !enabled {
		c.stopPreferredBackTickerLocked()
		if c.directOverride {
			wasDirect = true
			restoreID = c.lastUserProxyID
			restoreName = c.lastUserProxyName
		}
	}
	c.mu.Unlock()

	if wasDirect {
		candidates, proxies, _ := c.loadCandidates()
		restoreID = resolvePreferredProxyID(c.getSelectedProxyID(), restoreID, candidates)
		if restoreName == "" && restoreID != "" {
			restoreName = proxyNameFromID(restoreID, proxies)
		}
		if restoreID == "" {
			c.failClosedLocked("auto-switch disabled with no configured proxy", fmt.Errorf("no configured proxy"))
			return
		}
		if err := c.applyCorporateMode(restoreID, true); err != nil {
			log.Errorln("[net-switch] restore corporate routing on disable failed (%v) — failing closed", err)
			c.failClosedLocked("restore corporate routing failed on disable", err)
			return
		}
		c.mu.Lock()
		c.directOverride = false
		c.activeProxyID = restoreID
		c.activeProxyName = restoreName
		if c.state != stateCaptivePortal {
			c.state = stateIdle
		}
		c.mu.Unlock()
	} else if !enabled {
		c.mu.Lock()
		if c.state != stateCaptivePortal {
			c.state = stateIdle
		}
		c.mu.Unlock()
	}
	log.Infoln("[net-switch] enabled=%v", enabled)
}

// failClosedLocked closes the manager when a corporate-routing restore fails so
// unproxied direct traffic cannot leak. Caller MUST hold transitionMu (and NOT mu).
func (c *switchController) failClosedLocked(reason string, err error) {
	_ = c.closeManager()
	c.mu.Lock()
	c.directOverride = false
	c.captivePortalURL = ""
	c.activeProxyID = ""
	c.activeProxyName = ""
	c.state = stateNoInternet
	c.lastSwitchedAt = time.Now()
	c.lastReason = fmt.Sprintf("%s: %v", reason, err)
	c.mu.Unlock()

	c.broadcast(map[string]any{
		"proxyId":   "",
		"proxyName": "",
		"state":     string(stateNoInternet),
		"resumed":   false,
		"reason":    reason,
	})
}

// Status returns a snapshot of the current state.
func (c *switchController) Status() SwitchStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SwitchStatus{
		Enabled:          c.enabled,
		State:            c.state,
		ActiveProxyID:    c.activeProxyID,
		ActiveProxyName:  c.activeProxyName,
		CaptivePortalURL: c.captivePortalURL,
		LastSwitchedAt:   c.lastSwitchedAt,
		LastReason:       c.lastReason,
		LastTriggeredAt:  c.lastTriggeredAt,
		Probing:          c.probing,
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func sanitizeReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > maxTriggerReasonLen {
		reason = reason[:maxTriggerReasonLen]
	}
	return reason
}

func resolvePreferredProxyID(selectedID, lastUserID string, candidates []ProxyCandidate) string {
	if lastUserID != "" {
		return lastUserID
	}
	if selectedID != "" {
		return selectedID
	}
	if len(candidates) > 0 {
		return candidates[0].ID
	}
	return ""
}

// pickBestAliveProxy prefers preferredID when alive; otherwise picks the first
// alive candidate in configured priority order.
func pickBestAliveProxy(results []ProbeResult, preferredID string) (ProbeResult, bool) {
	if preferredID != "" {
		for _, r := range results {
			if r.ProxyID == preferredID && r.Alive {
				return r, true
			}
		}
	}
	for _, r := range results {
		if r.Alive {
			return r, true
		}
	}
	return ProbeResult{}, false
}

// ── Core probe cycle ─────────────────────────────────────────────────────────

func (c *switchController) loadCandidates() ([]ProxyCandidate, []map[string]any, error) {
	proxies, err := c.getProxies()
	if err != nil {
		return nil, nil, err
	}

	var candidates []ProxyCandidate
	for _, p := range proxies {
		id, _ := p["id"].(string)
		typ, _ := p["type"].(string)
		host, _ := p["server"].(string)
		port := 0
		switch v := p["port"].(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		}
		if id == "" || typ == "direct" || host == "" || port == 0 {
			continue
		}
		user, _ := p["username"].(string)
		pass := c.getProxyPassword(id)
		candidates = append(candidates, ProxyCandidate{
			ID: id, Host: host, Port: port, Username: user, Password: pass,
		})
	}
	return candidates, proxies, nil
}

func (c *switchController) runCycle(reason string) {
	log.Infoln("[net-switch] cycle start, reason=%s", reason)

	c.mu.Lock()
	startEpoch := c.epoch
	c.mu.Unlock()

	candidates, proxies, err := c.loadCandidates()
	if err != nil {
		log.Errorln("[net-switch] cannot read proxies: %v", err)
		return
	}
	if len(candidates) == 0 {
		log.Infoln("[net-switch] no HTTP/SOCKS proxies configured — skipping")
		return
	}

	selectedID := c.getSelectedProxyID()

	// Step 1: Probe all configured proxies in parallel (lock-free).
	results := c.probeProxies(candidates)

	// Step 2: Check if any configured proxy is reachable (200+TLS or 407).
	// If ANY configured proxy is alive, NEVER enter captive_portal or direct.
	if hasAliveProxy(results) {
		c.transitionMu.Lock()
		c.mu.Lock()
		if c.epoch != startEpoch || c.state == stateCaptivePortal {
			c.mu.Unlock()
			c.transitionMu.Unlock()
			return
		}
		if !c.isManagerStarted() {
			c.mu.Unlock()
			c.transitionMu.Unlock()
			return
		}
		enabled := c.enabled
		prevState := c.state
		directOverride := c.directOverride
		currentID := c.activeProxyID
		if currentID == "" || directOverride {
			currentID = selectedID
		}
		preferredID := resolvePreferredProxyID(selectedID, c.lastUserProxyID, candidates)
		manualHold := reason != "manual" && time.Now().Before(c.manualHoldUntil)
		c.mu.Unlock()

		// Already on a live corporate proxy (not in direct override)?
		if !directOverride && currentID != "" {
			for _, r := range results {
				if r.ProxyID == currentID && r.Alive {
					name := proxyNameFromID(r.ProxyID, proxies)
					log.Infoln("[net-switch] current proxy %s still alive (%dms) — no change",
						currentID, r.Latency.Milliseconds())
					c.mu.Lock()
					c.state = stateCorporate
					c.activeProxyID = r.ProxyID
					c.activeProxyName = name
					c.captivePortalURL = ""
					c.captiveCooldownUntil = time.Time{}
					if prevState != stateCorporate {
						c.lastSwitchedAt = time.Now()
						c.lastReason = "proxy " + name + " reachable (" + reason + ")"
					}
					c.stopPreferredBackTickerLocked()
					c.mu.Unlock()
					c.transitionMu.Unlock()

					if prevState != stateCorporate {
						c.broadcast(map[string]any{
							"proxyId":   r.ProxyID,
							"proxyName": name,
							"state":     string(stateCorporate),
						})
					}
					return
				}
			}
		}

		// Pick best alive proxy (preferring user's lastUserID if alive).
		best, ok := pickBestAliveProxy(results, preferredID)
		if !ok {
			c.transitionMu.Unlock()
			return
		}
		name := proxyNameFromID(best.ProxyID, proxies)

		if directOverride || (enabled && !manualHold) {
			log.Infoln("[net-switch] switching to proxy %s (%s) — %dms",
				best.ProxyID, name, best.Latency.Milliseconds())
			if err := c.applyCorporateMode(best.ProxyID, directOverride); err != nil {
				log.Errorln("[net-switch] applyCorporateMode(%s) failed: %v", best.ProxyID, err)
				if directOverride {
					c.failClosedLocked("corporate restore failed", err)
				}
				c.transitionMu.Unlock()
				return
			}
			c.mu.Lock()
			c.state = stateCorporate
			c.directOverride = false
			c.activeProxyID = best.ProxyID
			c.activeProxyName = name
			c.captivePortalURL = ""
			c.captiveCooldownUntil = time.Time{}
			c.lastSwitchedAt = time.Now()
			c.lastReason = "proxy " + name + " reachable (" + reason + ")"
			c.stopPreferredBackTickerLocked()
			c.mu.Unlock()
			c.transitionMu.Unlock()

			c.broadcast(map[string]any{
				"proxyId":   best.ProxyID,
				"proxyName": name,
				"state":     string(stateCorporate),
			})
			return
		}

		c.transitionMu.Unlock()
		log.Infoln("[net-switch] configured proxy %s (%s) reachable (%dms) — staying put",
			best.ProxyID, name, best.Latency.Milliseconds())
		return
	}

	// Step 3: All configured proxies failed — run 3-state direct/portal probe (lock-free).
	log.Infoln("[net-switch] all proxies unreachable, probing direct / captive portal")
	directRes := c.probeDirect()

	// Step 4: Re-verify epoch + current flags atomically under transitionMu before applying!
	c.transitionMu.Lock()
	c.mu.Lock()
	if c.epoch != startEpoch || c.state == stateCaptivePortal {
		c.mu.Unlock()
		c.transitionMu.Unlock()
		log.Infoln("[net-switch] cycle aborted: state or config changed while probing")
		return
	}
	if !c.isManagerStarted() {
		c.mu.Unlock()
		c.transitionMu.Unlock()
		return
	}
	enabled := c.enabled
	directOverride := c.directOverride
	lastUserID := c.lastUserProxyID
	manualHold := reason != "manual" && time.Now().Before(c.manualHoldUntil)
	inCaptiveCooldown := reason != "manual" && time.Now().Before(c.captiveCooldownUntil)
	c.mu.Unlock()

	switch directRes.State {
	case captivePortal:
		if inCaptiveCooldown {
			c.transitionMu.Unlock()
			log.Infoln("[net-switch] captive portal detected during safety cooldown — staying fail-closed")
			return
		}
		resumeID := resolvePreferredProxyID(selectedID, lastUserID, candidates)
		resumeName := proxyNameFromID(resumeID, proxies)
		c.enterCaptivePortalUnderTransitionLock(directRes.RedirectURL, resumeID, resumeName, candidates, reason)
		c.transitionMu.Unlock()
		return

	case directOK:
		if !enabled || manualHold {
			c.transitionMu.Unlock()
			log.Infoln("[net-switch] direct internet reachable, but auto-switch disabled or held (enabled=%v manualHold=%v) — staying fail-closed",
				enabled, manualHold)
			return
		}
		log.Infoln("[net-switch] direct works — switching to in-memory direct routing")
		if err := c.applyDirectMode(); err != nil {
			c.transitionMu.Unlock()
			log.Errorln("[net-switch] applyDirectMode failed: %v", err)
			return
		}
		c.mu.Lock()
		c.state = stateDirect
		c.directOverride = true
		c.activeProxyID = "direct"
		c.activeProxyName = "Direct"
		c.captivePortalURL = ""
		c.lastSwitchedAt = time.Now()
		c.lastReason = "no proxy reachable, direct connection active (" + reason + ")"
		c.mu.Unlock()

		c.startPreferredBackTicker(candidates)
		c.transitionMu.Unlock()

		c.broadcast(map[string]any{
			"proxyId":   "direct",
			"proxyName": "Direct",
			"state":     string(stateDirect),
		})
		return

	default: // noInternet
		log.Infoln("[net-switch] direct also failed — no internet (err=%v)", directRes.Err)
		if !enabled {
			c.transitionMu.Unlock()
			return
		}
		restoreID := resolvePreferredProxyID(selectedID, lastUserID, candidates)
		if directOverride {
			if restoreID == "" {
				c.failClosedLocked("no internet with no restore proxy", fmt.Errorf("empty restore proxy"))
				c.transitionMu.Unlock()
				return
			}
			if err := c.applyCorporateMode(restoreID, true); err != nil {
				log.Errorln("[net-switch] restore corporate routing on no_internet failed (%v) — failing closed", err)
				c.failClosedLocked("no internet corporate restore failed", err)
				c.transitionMu.Unlock()
				return
			}
		}
		restoreName := proxyNameFromID(restoreID, proxies)
		c.mu.Lock()
		c.state = stateNoInternet
		c.directOverride = false
		c.activeProxyID = restoreID
		c.activeProxyName = restoreName
		c.captivePortalURL = ""
		c.lastReason = "no internet (" + reason + ")"
		c.lastSwitchedAt = time.Now()
		c.mu.Unlock()

		// Poll in stateNoInternet too so returning to house LAN / WireGuard
		// recovers within 45s even when OS connectivity events are missed.
		c.startPreferredBackTicker(candidates)
		c.transitionMu.Unlock()

		c.broadcast(map[string]any{
			"proxyId":   "",
			"proxyName": "",
			"state":     string(stateNoInternet),
		})
	}
}

// ── Captive-portal pause & fast-poll loop ────────────────────────────────────

// enterCaptivePortalUnderTransitionLock pauses TUN/system proxy and spawns the
// fast-poll loop. Caller MUST hold c.transitionMu (and NOT c.mu).
func (c *switchController) enterCaptivePortalUnderTransitionLock(
	portalURL, resumeProxyID, resumeProxyName string,
	candidates []ProxyCandidate,
	reason string,
) {
	c.mu.Lock()
	if c.state == stateCaptivePortal {
		c.mu.Unlock()
		return
	}
	c.captiveGen++
	gen := c.captiveGen
	c.stopPreferredBackTickerLocked()
	c.stopCaptiveLoopLocked()

	stop := make(chan struct{})
	wake := make(chan struct{}, 1)
	c.captiveStopChan = stop
	c.captiveWakeChan = wake
	c.state = stateCaptivePortal
	c.directOverride = false
	c.captivePortalURL = portalURL
	c.captiveResumeProxyID = resumeProxyID
	c.captiveResumeProxyName = resumeProxyName
	c.lastSwitchedAt = time.Now()
	c.lastReason = "captive portal detected (" + reason + ")"
	c.mu.Unlock()

	log.Infoln("[net-switch] captive portal detected (url=%q, reason=%s) — pausing TUN/system proxy for sign-in",
		portalURL, reason)

	// Cleanly tear down TUN + system proxy (same path as pausedForNoNetwork).
	if err := c.closeManager(); err != nil {
		log.Errorln("[net-switch] closeManager on captive_portal failed: %v", err)
	}

	payload := map[string]any{
		"proxyId":   "",
		"proxyName": "",
		"state":     string(stateCaptivePortal),
	}
	if portalURL != "" {
		payload["portalUrl"] = portalURL
		payload["captivePortalUrl"] = portalURL
	}
	c.broadcast(payload)

	go c.runCaptivePortalLoop(gen, candidates, stop, wake)
}

func (c *switchController) runCaptivePortalLoop(
	gen uint64,
	candidates []ProxyCandidate,
	stop <-chan struct{},
	wake <-chan struct{},
) {
	pollInterval := c.getCaptivePollInterval()
	maxDuration := c.getCaptiveMaxDuration()

	// Use a Timer reset AFTER each probe completes (instead of a Ticker) so a
	// slow 4.5s probe never triggers back-to-back probes with 0ms gap.
	pollTimer := time.NewTimer(pollInterval)
	maxTimer := time.NewTimer(maxDuration)
	defer pollTimer.Stop()
	defer maxTimer.Stop()

	resetPollTimer := func() {
		if !pollTimer.Stop() {
			select {
			case <-pollTimer.C:
			default:
			}
		}
		pollTimer.Reset(pollInterval)
	}

	checkOnce := func() bool {
		c.mu.Lock()
		if c.state != stateCaptivePortal || c.captiveGen != gen {
			c.mu.Unlock()
			return true
		}
		c.mu.Unlock()

		// 1. Check if any configured proxy became reachable.
		proxyResults := c.probeProxies(candidates)
		if hasAliveProxy(proxyResults) {
			c.exitCaptivePortal(gen, candidates, proxyResults, false, false, "proxy reachable")
			return true
		}

		// 2. Check if the captive portal cleared (200 Success / directOK).
		directRes := c.probeDirect()
		if directRes.State == directOK {
			// Requirement: re-probe configured proxies first before deciding
			// corporate vs direct vs fail-closed resume.
			proxyResults = c.probeProxies(candidates)
			c.exitCaptivePortal(gen, candidates, proxyResults, true, false, "captive portal cleared")
			return true
		}

		if directRes.State == captivePortal && directRes.RedirectURL != "" {
			c.mu.Lock()
			if c.state == stateCaptivePortal && c.captiveGen == gen && c.captivePortalURL == "" {
				c.captivePortalURL = directRes.RedirectURL
			}
			c.mu.Unlock()
		}
		return false
	}

	for {
		select {
		case <-stop:
			return
		case <-wake:
			if checkOnce() {
				return
			}
			resetPollTimer()
		case <-pollTimer.C:
			if checkOnce() {
				return
			}
			resetPollTimer()
		case <-maxTimer.C:
			c.mu.Lock()
			if c.state != stateCaptivePortal || c.captiveGen != gen {
				c.mu.Unlock()
				return
			}
			c.mu.Unlock()

			log.Warnln("[net-switch] captive portal safety timeout (%v) reached — re-probing and resuming Lux",
				maxDuration)
			proxyResults := c.probeProxies(candidates)
			directRes := c.probeDirect()
			c.exitCaptivePortal(gen, candidates, proxyResults, directRes.State == directOK, true, "captive portal safety timeout")
			return
		}
	}
}

func (c *switchController) exitCaptivePortal(
	gen uint64,
	candidates []ProxyCandidate,
	proxyResults []ProbeResult,
	directIsOK bool,
	isSafetyTimeout bool,
	exitReason string,
) {
	// Serialize the entire exit transition under transitionMu so a concurrent
	// ManualStop / ManualStart / SetEnabled can never interleave with
	// startManager() + apply*() and we never close a newer session's manager.
	c.transitionMu.Lock()

	c.mu.Lock()
	if c.state != stateCaptivePortal || c.captiveGen != gen {
		c.mu.Unlock()
		c.transitionMu.Unlock()
		return
	}
	enabled := c.enabled
	resumeID := c.captiveResumeProxyID
	resumeName := c.captiveResumeProxyName
	lastUserID := c.lastUserProxyID
	lastUserName := c.lastUserProxyName
	c.stopCaptiveLoopLocked()
	c.mu.Unlock()

	proxies, _ := c.getProxies()
	preferredID := resolvePreferredProxyID(resumeID, lastUserID, candidates)

	// Path 1: Any configured proxy is reachable -> resume Lux on it (preferring
	// the user's chosen proxy if alive).
	if best, ok := pickBestAliveProxy(proxyResults, preferredID); ok {
		name := proxyNameFromID(best.ProxyID, proxies)
		log.Infoln("[net-switch] exiting captive_portal (%s) -> resuming corporate proxy %s (%s)",
			exitReason, best.ProxyID, name)

		if err := c.startManager(); err != nil {
			c.handleCaptiveResumeErrorUnderTransitionLock(gen, candidates, exitReason, err)
			c.transitionMu.Unlock()
			return
		}
		if err := c.applyCorporateMode(best.ProxyID, false); err != nil {
			_ = c.closeManager()
			c.handleCaptiveResumeErrorUnderTransitionLock(gen, candidates, exitReason+" (apply proxy failed)", err)
			c.transitionMu.Unlock()
			return
		}

		c.mu.Lock()
		c.state = stateCorporate
		c.directOverride = false
		c.activeProxyID = best.ProxyID
		c.activeProxyName = name
		c.captivePortalURL = ""
		c.captiveCooldownUntil = time.Time{}
		c.lastSwitchedAt = time.Now()
		c.lastReason = exitReason + " — resumed on " + name
		c.stopPreferredBackTickerLocked()
		c.mu.Unlock()
		c.transitionMu.Unlock()

		c.broadcast(map[string]any{
			"proxyId":   best.ProxyID,
			"proxyName": name,
			"state":     string(stateCorporate),
			"resumed":   true,
			"reason":    exitReason,
		})
		return
	}

	// Path 2: No proxy reachable, autoSwitchEnabled == true, direct is OK ->
	// resume Lux in stateDirect (in-memory bypass_all) and start 45s recovery poll.
	if enabled && directIsOK {
		log.Infoln("[net-switch] exiting captive_portal (%s) -> resuming in direct mode (autoSwitchEnabled=true)",
			exitReason)

		if err := c.startManager(); err != nil {
			c.handleCaptiveResumeErrorUnderTransitionLock(gen, candidates, exitReason, err)
			c.transitionMu.Unlock()
			return
		}
		if err := c.applyDirectMode(); err != nil {
			_ = c.closeManager()
			c.handleCaptiveResumeErrorUnderTransitionLock(gen, candidates, exitReason+" (apply direct failed)", err)
			c.transitionMu.Unlock()
			return
		}

		c.mu.Lock()
		c.state = stateDirect
		c.directOverride = true
		c.activeProxyID = "direct"
		c.activeProxyName = "Direct"
		c.captivePortalURL = ""
		c.lastSwitchedAt = time.Now()
		c.lastReason = exitReason + " — direct connection active"
		c.mu.Unlock()

		c.startPreferredBackTicker(candidates)
		c.transitionMu.Unlock()

		c.broadcast(map[string]any{
			"proxyId":   "direct",
			"proxyName": "Direct",
			"state":     string(stateDirect),
			"resumed":   true,
			"reason":    exitReason,
		})
		return
	}

	// Path 3: Fail-closed resume on user's configured proxy (either
	// autoSwitchEnabled == false, or 3-minute safety timeout fired without direct).
	targetID := resolvePreferredProxyID(c.getSelectedProxyID(), preferredID, candidates)
	targetName := resumeName
	if targetName == "" {
		targetName = lastUserName
	}
	if targetName == "" && targetID != "" {
		targetName = proxyNameFromID(targetID, proxies)
	}

	if targetID == "" {
		c.handleCaptiveResumeErrorUnderTransitionLock(gen, candidates, exitReason, fmt.Errorf("no configured proxy to resume"))
		c.transitionMu.Unlock()
		return
	}

	log.Infoln("[net-switch] exiting captive_portal (%s) -> resuming fail-closed on %s (%s)",
		exitReason, targetName, targetID)

	if err := c.startManager(); err != nil {
		c.handleCaptiveResumeErrorUnderTransitionLock(gen, candidates, exitReason, err)
		c.transitionMu.Unlock()
		return
	}
	if err := c.applyCorporateMode(targetID, false); err != nil {
		_ = c.closeManager()
		c.handleCaptiveResumeErrorUnderTransitionLock(gen, candidates, exitReason+" (apply corporate failed)", err)
		c.transitionMu.Unlock()
		return
	}

	nextState := stateCorporate
	if enabled && !directIsOK {
		nextState = stateNoInternet
	}

	c.mu.Lock()
	c.state = nextState
	c.directOverride = false
	c.activeProxyID = targetID
	c.activeProxyName = targetName
	c.captivePortalURL = ""
	if isSafetyTimeout {
		// Prevent immediate automatic re-entry into captive_portal after the
		// 3-minute cap so a hostile/abandoned portal cannot loop unproxied.
		c.captiveCooldownUntil = time.Now().Add(c.getCaptiveCooldown())
	}
	c.lastSwitchedAt = time.Now()
	c.lastReason = exitReason + " — resumed fail-closed"
	c.mu.Unlock()

	if nextState == stateNoInternet {
		c.startPreferredBackTicker(candidates)
	}
	c.transitionMu.Unlock()

	c.broadcast(map[string]any{
		"proxyId":   targetID,
		"proxyName": targetName,
		"state":     string(nextState),
		"resumed":   true,
		"reason":    exitReason,
	})
}

// handleCaptiveResumeErrorUnderTransitionLock handles a failure to restart the
// manager after captive portal. Caller MUST hold c.transitionMu (and NOT c.mu).
func (c *switchController) handleCaptiveResumeErrorUnderTransitionLock(
	gen uint64,
	candidates []ProxyCandidate,
	exitReason string,
	err error,
) {
	log.Errorln("[net-switch] failed to resume manager after captive_portal (%s): %v", exitReason, err)
	c.mu.Lock()
	if c.captiveGen != gen {
		c.mu.Unlock()
		return
	}
	c.state = stateNoInternet
	c.directOverride = false
	c.captivePortalURL = ""
	c.activeProxyID = ""
	c.activeProxyName = ""
	c.captiveCooldownUntil = time.Now().Add(c.getCaptiveCooldown())
	c.lastSwitchedAt = time.Now()
	c.lastReason = exitReason + " — resume failed: " + err.Error()
	c.mu.Unlock()

	// Start recovery ticker so lux_core also keeps retrying on its own in
	// addition to Flutter's pausedForNoNetwork / watchdog safety net.
	if len(candidates) > 0 {
		c.startPreferredBackTicker(candidates)
	}

	c.broadcast(map[string]any{
		"proxyId":   "",
		"proxyName": "",
		"state":     string(stateNoInternet),
		"resumed":   false,
		"reason":    exitReason,
	})
}

func (c *switchController) stopCaptiveLoopLocked() {
	if c.captiveStopChan != nil {
		close(c.captiveStopChan)
		c.captiveStopChan = nil
	}
	c.captiveWakeChan = nil
}

func hasAliveProxy(results []ProbeResult) bool {
	for _, r := range results {
		if r.Alive {
			return true
		}
	}
	return false
}

// ── Live routing switch helpers (no "type":"direct" config entry required) ───

// defaultApplyDirectMode switches active routing in memory to bypass_all
// without mutating config.json (selected.proxy and selected.rule remain intact).
func defaultApplyDirectMode() error {
	if !manager.GetIsStarted() {
		return nil
	}
	bypassEngine, err := rule_engine.New("bypass_all", nil)
	if err != nil {
		return fmt.Errorf("build in-memory bypass_all engine: %w", err)
	}
	matcher.UpdateRuleEngine(bypassEngine)
	dns.ResetCache()
	log.Infoln("[net-switch] applied in-memory bypass_all direct routing (config.json unchanged)")
	return nil
}

// defaultApplyCorporateMode parses the target proxy BEFORE persisting selection,
// restores the configured rule engine from config.json, and closes existing
// tracked connections when leaving direct mode so long-lived direct sockets
// cannot keep bypassing the corporate proxy.
func defaultApplyCorporateMode(proxyID string, closeExisting bool) error {
	var rawProxy map[string]any
	needSelect := false

	if proxyID != "" {
		data, err := configuration.Read()
		if err != nil {
			return err
		}
		p, err := configuration.GetProxy(proxyID)
		if err != nil {
			return fmt.Errorf("proxy %q not found: %w", proxyID, err)
		}
		rawProxy = p
		needSelect = data.Selected.Proxy != proxyID
	} else {
		p, err := configuration.GetSelectedProxy()
		if err != nil {
			return err
		}
		rawProxy = p
	}

	// Parse before mutating config.json so invalid configs never leave config
	// and runtime out of sync.
	proxy, err := adapter.ParseProxy(rawProxy)
	if err != nil {
		return err
	}

	if needSelect {
		if err := configuration.SetSelectedId("proxy", proxyID); err != nil {
			return err
		}
	}

	if manager.GetIsStarted() {
		id, _ := rawProxy["id"].(string)
		conn.UpdateProxyWithId(proxy, id)
		if _, err := executor.UpdateRule(); err != nil {
			return err
		}
		if closeExisting {
			statistic.DefaultManager.CloseAllConnections()
		}
	}
	return nil
}

// proxyNameFromID returns the name of a proxy given its ID.
func proxyNameFromID(id string, proxies []map[string]any) string {
	for _, p := range proxies {
		if p["id"] == id {
			if n, ok := p["name"].(string); ok && n != "" {
				return n
			}
			host, _ := p["server"].(string)
			port := ""
			switch v := p["port"].(type) {
			case float64:
				port = fmt.Sprintf("%d", int(v))
			case int:
				port = fmt.Sprintf("%d", v)
			}
			return host + ":" + port
		}
	}
	return id
}

// getProxyPassword retrieves the decrypted password for a proxy.
func getProxyPassword(proxyID string) string {
	p, err := configuration.GetProxy(proxyID)
	if err != nil {
		return ""
	}
	pass, _ := p["password"].(string)
	return pass
}

// ── Preferred-proxy-back recovery ticker ─────────────────────────────────────
// While in DIRECT or NO_INTERNET, poll every 45s to detect when a house or
// WireGuard proxy returns — even if OS connectivity events miss an SSID roam.

func (c *switchController) startPreferredBackTicker(candidates []ProxyCandidate) {
	interval := c.getPreferredBackInterval()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopPreferredBackTickerLocked()
	stop := make(chan struct{})
	c.stopChan = stop
	ticker := time.NewTicker(interval)
	c.preferredBackTicker = ticker
	go func() {
		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				st := c.state
				enabled := c.enabled
				stale := c.stopChan != stop
				c.mu.Unlock()

				// In stateNoInternet after a failed captive resume, keep retrying
				// even when enabled==false if the manager is still stopped.
				if stale || (st != stateDirect && st != stateNoInternet) {
					c.mu.Lock()
					if c.stopChan == stop {
						c.stopPreferredBackTickerLocked()
					}
					c.mu.Unlock()
					return
				}
				if !enabled && st == stateDirect {
					c.mu.Lock()
					if c.stopChan == stop {
						c.stopPreferredBackTickerLocked()
					}
					c.mu.Unlock()
					return
				}

				// 1. Always re-probe configured proxies first (lock-free).
				results := c.probeProxies(candidates)
				if hasAliveProxy(results) {
					c.transitionMu.Lock()
					c.mu.Lock()
					if c.stopChan != stop || (c.state != stateDirect && c.state != stateNoInternet) {
						c.mu.Unlock()
						c.transitionMu.Unlock()
						return
					}
					wasDirect := c.directOverride
					preferredID := resolvePreferredProxyID(c.getSelectedProxyID(), c.lastUserProxyID, candidates)
					curState := c.state
					c.mu.Unlock()

					best, ok := pickBestAliveProxy(results, preferredID)
					if !ok {
						c.transitionMu.Unlock()
						continue
					}
					proxies, _ := c.getProxies()
					name := proxyNameFromID(best.ProxyID, proxies)
					log.Infoln("[net-switch] preferred proxy %s (%s) back — switching from %s",
						best.ProxyID, name, curState)

					restarted := false
					if !c.isManagerStarted() {
						if err := c.startManager(); err != nil {
							log.Errorln("[net-switch] recovery startManager failed: %v", err)
							c.transitionMu.Unlock()
							continue
						}
						restarted = true
					}
					if err := c.applyCorporateMode(best.ProxyID, wasDirect); err != nil {
						log.Errorln("[net-switch] applyCorporateMode(%s) failed: %v", best.ProxyID, err)
						if wasDirect || restarted {
							c.failClosedLocked("recovery apply corporate failed", err)
						}
						c.transitionMu.Unlock()
						continue
					}

					c.mu.Lock()
					if c.stopChan != stop {
						c.mu.Unlock()
						c.transitionMu.Unlock()
						return
					}
					c.state = stateCorporate
					c.directOverride = false
					c.activeProxyID = best.ProxyID
					c.activeProxyName = name
					c.captivePortalURL = ""
					c.captiveCooldownUntil = time.Time{}
					c.lastSwitchedAt = time.Now()
					c.lastReason = "preferred proxy " + name + " back online"
					c.stopPreferredBackTickerLocked()
					c.mu.Unlock()
					c.transitionMu.Unlock()

					payload := map[string]any{
						"proxyId":   best.ProxyID,
						"proxyName": name,
						"state":     string(stateCorporate),
					}
					if restarted {
						payload["resumed"] = true
					}
					c.broadcast(payload)
					return
				}

				// 2. If in stateNoInternet, check whether connectivity recovered
				//    (or if a failed captive resume can now restart fail-closed).
				if st == stateNoInternet {
					directRes := c.probeDirect()

					c.transitionMu.Lock()
					c.mu.Lock()
					if c.stopChan != stop || c.state != stateNoInternet {
						c.mu.Unlock()
						c.transitionMu.Unlock()
						return
					}
					curEnabled := c.enabled
					inCooldown := time.Now().Before(c.captiveCooldownUntil)
					preferredID := resolvePreferredProxyID(c.getSelectedProxyID(), c.lastUserProxyID, candidates)
					c.mu.Unlock()

					// If manager was stopped by a failed captive resume and
					// auto-switch is off, retry fail-closed startManager().
					if !curEnabled {
						if !c.isManagerStarted() && directRes.State == directOK {
							if err := c.startManager(); err == nil {
								if err := c.applyCorporateMode(preferredID, false); err == nil {
									proxies, _ := c.getProxies()
									name := proxyNameFromID(preferredID, proxies)
									c.mu.Lock()
									c.state = stateCorporate
									c.directOverride = false
									c.activeProxyID = preferredID
									c.activeProxyName = name
									c.lastSwitchedAt = time.Now()
									c.lastReason = "fail-closed manager resumed (recovery-poll)"
									c.stopPreferredBackTickerLocked()
									c.mu.Unlock()
									c.transitionMu.Unlock()
									c.broadcast(map[string]any{
										"proxyId":   preferredID,
										"proxyName": name,
										"state":     string(stateCorporate),
										"resumed":   true,
									})
									return
								}
								_ = c.closeManager()
							}
						}
						c.transitionMu.Unlock()
						continue
					}

					switch directRes.State {
					case captivePortal:
						if !inCooldown && c.isManagerStarted() {
							proxies, _ := c.getProxies()
							c.enterCaptivePortalUnderTransitionLock(
								directRes.RedirectURL,
								preferredID,
								proxyNameFromID(preferredID, proxies),
								candidates,
								"recovery-poll",
							)
							c.transitionMu.Unlock()
							return
						}
						c.transitionMu.Unlock()
					case directOK:
						if !c.isManagerStarted() {
							if err := c.startManager(); err != nil {
								c.transitionMu.Unlock()
								continue
							}
						}
						if err := c.applyDirectMode(); err != nil {
							log.Errorln("[net-switch] applyDirectMode in recovery failed: %v", err)
							c.transitionMu.Unlock()
							continue
						}
						c.mu.Lock()
						if c.stopChan != stop || !c.enabled || c.state != stateNoInternet {
							c.mu.Unlock()
							c.transitionMu.Unlock()
							return
						}
						c.state = stateDirect
						c.directOverride = true
						c.activeProxyID = "direct"
						c.activeProxyName = "Direct"
						c.lastSwitchedAt = time.Now()
						c.lastReason = "direct connection recovered (recovery-poll)"
						c.mu.Unlock()
						c.transitionMu.Unlock()

						c.broadcast(map[string]any{
							"proxyId":   "direct",
							"proxyName": "Direct",
							"state":     string(stateDirect),
							"resumed":   true,
						})
					default:
						c.transitionMu.Unlock()
					}
				}
			case <-stop:
				return
			}
		}
	}()
}

func (c *switchController) stopPreferredBackTickerLocked() {
	if c.preferredBackTicker != nil {
		c.preferredBackTicker.Stop()
		c.preferredBackTicker = nil
	}
	if c.stopChan != nil {
		close(c.stopChan)
		c.stopChan = nil
	}
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func netSwitchRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/status", netSwitchStatus)
	r.Post("/trigger", netSwitchTrigger)
	r.Get("/config", netSwitchGetConfig)
	r.Post("/config", netSwitchSetConfig)
	r.Post("/manual-select", netSwitchManualSelect)
	return r
}

func netSwitchStatus(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, switchCtrl.Status())
}

func netSwitchTrigger(w http.ResponseWriter, r *http.Request) {
	reason := "manual"
	if r.Body != nil {
		var req struct {
			Reason string `json:"reason"`
		}
		err := render.DecodeJSON(r.Body, &req)
		if err != nil && err != io.EOF {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, NewError("invalid body"))
			return
		}
		if req.Reason != "" {
			reason = sanitizeReason(req.Reason)
		}
	}
	switchCtrl.Trigger(reason)
	render.JSON(w, r, render.M{"ok": true})
}

func netSwitchGetConfig(w http.ResponseWriter, r *http.Request) {
	switchCtrl.mu.Lock()
	enabled := switchCtrl.enabled
	lastID := switchCtrl.lastUserProxyID
	lastName := switchCtrl.lastUserProxyName
	switchCtrl.mu.Unlock()
	render.JSON(w, r, render.M{
		"enabled":           enabled,
		"lastUserProxyId":   lastID,
		"lastUserProxyName": lastName,
	})
}

func netSwitchSetConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled         *bool  `json:"enabled"`
		LastUserProxyID string `json:"lastUserProxyId"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("invalid body"))
		return
	}
	if req.LastUserProxyID != "" {
		proxies, err := switchCtrl.getProxies()
		if err == nil {
			found := false
			for _, p := range proxies {
				if id, _ := p["id"].(string); id == req.LastUserProxyID {
					found = true
					break
				}
			}
			if !found {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, NewError("unknown lastUserProxyId"))
				return
			}
			name := proxyNameFromID(req.LastUserProxyID, proxies)
			switchCtrl.mu.Lock()
			switchCtrl.lastUserProxyID = req.LastUserProxyID
			switchCtrl.lastUserProxyName = name
			switchCtrl.mu.Unlock()
		}
	}
	if req.Enabled != nil {
		switchCtrl.SetEnabled(*req.Enabled)
	}
	render.JSON(w, r, render.M{"ok": true})
}

func netSwitchManualSelect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProxyID   string `json:"proxyId"`
		ProxyName string `json:"proxyName"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("invalid body"))
		return
	}
	if req.ProxyID == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("proxyId required"))
		return
	}
	switchCtrl.NotifyManualSelect(req.ProxyID, req.ProxyName)
	render.JSON(w, r, render.M{"ok": true})
}
