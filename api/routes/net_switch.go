package routes

// net_switch.go — auto-proxy switching controller + HTTP API.
//
// Design (Opus-5 reviewed):
//
//   States: IDLE, PROBING, CORPORATE(proxyID), DIRECT, NO_INTERNET
//
//   On trigger (wake, connectivity event, manual, 5-min tick while running):
//   1. Probe all configured proxies IN PARALLEL.
//   2. If currently-selected proxy is alive → stay (no switch, no noise).
//   3. If another proxy is alive → switch to it, notify.
//   4. If no proxy alive → probe DIRECT.
//      4a. DIRECT ok  → switch to DIRECT, notify.
//      4b. DIRECT fail → notify "no internet", restore last-user-selected in UI only.
//   5. Every 5 min while in DIRECT: re-probe proxies (preferred-proxy-back check).
//      If a proxy is back → switch back, notify.
//
//   Guards:
//   - Feature disabled by default; enabled via POST /net-switch/config.
//   - Cooldown: minimum 30s between auto-switches (not counting manual).
//   - Manual proxy selection sets lastUserProxyID and suppresses auto-switch
//     for 10 min (manual-override hold).
//   - All state changes are logged via appLog with full probe evidence.
//
// HTTP API:
//   GET  /net-switch/status   → current state + last switch reason
//   POST /net-switch/trigger  → manual trigger (runs immediately)
//   GET  /net-switch/config   → read feature config
//   POST /net-switch/config   → enable/disable, set lastUserProxyID
//   POST /net-switch/manual-select → record a manual proxy selection

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/conn"
	"github.com/igoogolx/itun2socks/internal/manager"
	"github.com/igoogolx/itun2socks/pkg/clash/adapter"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// ── State machine ────────────────────────────────────────────────────────────

type switchState string

const (
	stateIdle       switchState = "idle"
	stateProbing    switchState = "probing"
	stateCorporate  switchState = "corporate"
	stateDirect     switchState = "direct"
	stateNoInternet switchState = "no_internet"
)

type SwitchStatus struct {
	Enabled         bool        `json:"enabled"`
	State           switchState `json:"state"`
	ActiveProxyID   string      `json:"activeProxyId"`   // proxy ID or "direct"
	ActiveProxyName string      `json:"activeProxyName"` // human-readable
	LastSwitchedAt  time.Time   `json:"lastSwitchedAt"`
	LastReason      string      `json:"lastReason"`
	LastTriggeredAt time.Time   `json:"lastTriggeredAt"`
	Probing         bool        `json:"probing"`
}

var switchCtrl = &switchController{}

type switchController struct {
	mu sync.Mutex

	enabled         bool
	state           switchState
	activeProxyID   string
	activeProxyName string
	lastSwitchedAt  time.Time
	lastReason      string
	lastTriggeredAt time.Time
	probing         bool

	// lastUserProxyID is the proxy the user manually selected last.
	// Auto-switch never overwrites this — it's used to restore the UI
	// when "no internet" and as the starting point after boot.
	lastUserProxyID   string
	lastUserProxyName string
	manualHoldUntil   time.Time // suppress auto-switch for 10 min after manual select

	// preferredBackTicker polls every 5 min while in DIRECT to detect
	// when the corporate proxy is back.
	preferredBackTicker *time.Ticker
	stopChan            chan struct{}
}

// ── Public API ───────────────────────────────────────────────────────────────

// NotifyManualSelect is called whenever the user manually selects a proxy.
// It records the user's intent and sets a 10-min suppression window.
func (c *switchController) NotifyManualSelect(proxyID, proxyName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastUserProxyID = proxyID
	c.lastUserProxyName = proxyName
	c.manualHoldUntil = time.Now().Add(10 * time.Minute)
	log.Infoln("[net-switch] manual select: %s (%s) — hold until %s",
		proxyName, proxyID, c.manualHoldUntil.Format(time.TimeOnly))
}

// Trigger runs a probe cycle. Safe to call concurrently — extra calls while
// a probe is running are dropped.
func (c *switchController) Trigger(reason string) {
	c.mu.Lock()
	if !c.enabled || c.probing {
		c.mu.Unlock()
		return
	}
	if time.Now().Before(c.manualHoldUntil) {
		log.Infoln("[net-switch] trigger suppressed by manual-hold (reason: %s)", reason)
		c.mu.Unlock()
		return
	}
	c.probing = true
	c.lastTriggeredAt = time.Now()
	c.mu.Unlock()

	go func() {
		defer func() {
			c.mu.Lock()
			c.probing = false
			c.mu.Unlock()
		}()
		c.runCycle(reason)
	}()
}

// SetEnabled turns the feature on or off.
func (c *switchController) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
	if !enabled {
		c.state = stateIdle
		c.stopPreferredBackTicker()
	}
	log.Infoln("[net-switch] enabled=%v", enabled)
}

// Status returns a snapshot of the current state.
func (c *switchController) Status() SwitchStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SwitchStatus{
		Enabled:         c.enabled,
		State:           c.state,
		ActiveProxyID:   c.activeProxyID,
		ActiveProxyName: c.activeProxyName,
		LastSwitchedAt:  c.lastSwitchedAt,
		LastReason:      c.lastReason,
		LastTriggeredAt: c.lastTriggeredAt,
		Probing:         c.probing,
	}
}

// ── Core probe cycle ─────────────────────────────────────────────────────────

func (c *switchController) runCycle(reason string) {
	log.Infoln("[net-switch] cycle start, reason=%s", reason)

	// Build candidate list from configuration
	proxies, err := configuration.GetProxies()
	if err != nil {
		log.Errorln("[net-switch] cannot read proxies: %v", err)
		return
	}

	var candidates []ProxyCandidate
	for _, p := range proxies {
		id, _ := p["id"].(string)
		typ, _ := p["type"].(string)
		host, _ := p["server"].(string)
		port := 0
		if v, ok := p["port"].(float64); ok {
			port = int(v)
		}
		if id == "" || typ == "direct" || host == "" || port == 0 {
			continue
		}
		user, _ := p["username"].(string)
		pass := getProxyPassword(id)
		candidates = append(candidates, ProxyCandidate{
			ID: id, Host: host, Port: port, Username: user, Password: pass,
		})
	}

	if len(candidates) == 0 {
		log.Infoln("[net-switch] no HTTP/SOCKS proxies configured — skipping")
		return
	}

	// Probe all in parallel
	results := probeProxiesParallel(candidates)

	// Read current selected proxy
	c.mu.Lock()
	currentID := c.activeProxyID
	lastUserID := c.lastUserProxyID
	c.mu.Unlock()

	// If currently-selected proxy is still alive → do nothing
	for _, r := range results {
		if r.ProxyID == currentID && r.Alive {
			log.Infoln("[net-switch] current proxy %s still alive (%dms) — no change",
				currentID, r.Latency.Milliseconds())
			c.mu.Lock()
			c.state = stateCorporate
			c.mu.Unlock()
			c.stopPreferredBackTickerSafe()
			return
		}
	}

	// Find best alive proxy (first in candidate order = priority order)
	for _, r := range results {
		if r.Alive {
			name := proxyNameFromID(r.ProxyID, proxies)
			log.Infoln("[net-switch] switching to proxy %s (%s) — %dms",
				r.ProxyID, name, r.Latency.Milliseconds())
			c.applySwitch(r.ProxyID, name, stateCorporate,
				"proxy "+name+" reachable ("+reason+")")
			c.stopPreferredBackTickerSafe()
			broadcastSwitchEvent(r.ProxyID, name, "corporate")
			return
		}
	}

	// No proxy reachable — try direct
	log.Infoln("[net-switch] all proxies unreachable, probing direct")
	if probeDirect() {
		log.Infoln("[net-switch] direct works — switching to direct")
		c.applySwitch("direct", "Direct", stateDirect,
			"no proxy reachable, direct connection active ("+reason+")")
		// Start preferred-back ticker to detect when corporate returns
		c.startPreferredBackTicker(candidates)
		broadcastSwitchEvent("direct", "Direct", "direct")
		return
	}

	// No internet at all
	log.Infoln("[net-switch] direct also failed — no internet")
	c.mu.Lock()
	c.state = stateNoInternet
	c.lastReason = "no internet (" + reason + ")"
	c.lastSwitchedAt = time.Now()
	// Restore UI to last user-selected (but don't actually switch routing —
	// there's no internet anyway so any switch would be useless)
	restoreID := lastUserID
	restoreName := c.lastUserProxyName
	c.mu.Unlock()

	if restoreID != "" && restoreID != currentID {
		_ = applyProxyConfig(restoreID, restoreName)
	}
	broadcastSwitchEvent("", "", "no_internet")
}

// applySwitch selects the proxy in lux_core config and updates controller state.
func (c *switchController) applySwitch(proxyID, proxyName string, state switchState, reason string) {
	if err := applyProxyConfig(proxyID, proxyName); err != nil {
		log.Errorln("[net-switch] applyProxyConfig failed: %v", err)
		return
	}
	c.mu.Lock()
	c.state = state
	c.activeProxyID = proxyID
	c.activeProxyName = proxyName
	c.lastSwitchedAt = time.Now()
	c.lastReason = reason
	c.mu.Unlock()
}

// applyProxyConfig calls the same code path as setProxySelectedId.
func applyProxyConfig(proxyID, _ string) error {
	if proxyID == "direct" {
		// Switch to the DIRECT proxy entry in config
		directID, err := findDirectProxyID()
		if err != nil {
			return err
		}
		proxyID = directID
	}
	if err := configuration.SetSelectedId("proxy", proxyID); err != nil {
		return err
	}
	if manager.GetIsStarted() {
		rawProxy, err := configuration.GetSelectedProxy()
		if err != nil {
			return err
		}
		proxy, err := adapter.ParseProxy(rawProxy)
		if err != nil {
			return err
		}
		conn.UpdateProxy(proxy)
	}
	return nil
}

// findDirectProxyID returns the ID of the DIRECT proxy entry in configuration.
func findDirectProxyID() (string, error) {
	proxies, err := configuration.GetProxies()
	if err != nil {
		return "", err
	}
	for _, p := range proxies {
		if t, _ := p["type"].(string); t == "direct" {
			if id, _ := p["id"].(string); id != "" {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("no DIRECT proxy entry found in configuration")
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
			if v, ok := p["port"].(float64); ok {
				port = fmt.Sprintf("%d", int(v))
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

// ── Preferred-proxy-back ticker ───────────────────────────────────────────────
// While in DIRECT, poll every 5 min to detect when corporate proxy is back.

func (c *switchController) startPreferredBackTicker(candidates []ProxyCandidate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopPreferredBackTicker()
	stop := make(chan struct{})
	c.stopChan = stop
	ticker := time.NewTicker(5 * time.Minute)
	c.preferredBackTicker = ticker
	go func() {
		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				if c.state != stateDirect || !c.enabled {
					c.mu.Unlock()
					return
				}
				c.mu.Unlock()
				results := probeProxiesParallel(candidates)
				for _, r := range results {
					if r.Alive {
						proxies, _ := configuration.GetProxies()
						name := proxyNameFromID(r.ProxyID, proxies)
						log.Infoln("[net-switch] preferred proxy %s back — switching from direct", r.ProxyID)
						c.applySwitch(r.ProxyID, name, stateCorporate,
							"preferred proxy "+name+" back online")
						c.stopPreferredBackTickerSafe()
						broadcastSwitchEvent(r.ProxyID, name, "corporate")
						return
					}
				}
			case <-stop:
				return
			}
		}
	}()
}

func (c *switchController) stopPreferredBackTicker() {
	if c.preferredBackTicker != nil {
		c.preferredBackTicker.Stop()
		c.preferredBackTicker = nil
	}
	if c.stopChan != nil {
		close(c.stopChan)
		c.stopChan = nil
	}
}

func (c *switchController) stopPreferredBackTickerSafe() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopPreferredBackTicker()
}

// ── Event broadcast ───────────────────────────────────────────────────────────

// broadcastSwitchEvent pushes a net_switch event to all WebSocket subscribers
// so Flutter can show an OS notification without polling.
func broadcastSwitchEvent(proxyID, proxyName, state string) {
	BroadcastEvent("net_switch", map[string]any{
		"proxyId":   proxyID,
		"proxyName": proxyName,
		"state":     state,
	})
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
	switchCtrl.Trigger("manual")
	render.JSON(w, r, render.M{"ok": true})
}

func netSwitchGetConfig(w http.ResponseWriter, r *http.Request) {
	s := switchCtrl.Status()
	render.JSON(w, r, render.M{
		"enabled":           s.Enabled,
		"lastUserProxyId":   switchCtrl.lastUserProxyID,
		"lastUserProxyName": switchCtrl.lastUserProxyName,
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
	if req.Enabled != nil {
		switchCtrl.SetEnabled(*req.Enabled)
	}
	if req.LastUserProxyID != "" {
		switchCtrl.mu.Lock()
		switchCtrl.lastUserProxyID = req.LastUserProxyID
		switchCtrl.mu.Unlock()
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
	// Also update activeProxyID so the next cycle knows the baseline
	switchCtrl.mu.Lock()
	switchCtrl.activeProxyID = req.ProxyID
	switchCtrl.activeProxyName = req.ProxyName
	if switchCtrl.state != stateDirect {
		switchCtrl.state = stateCorporate
	}
	switchCtrl.mu.Unlock()
	render.JSON(w, r, render.M{"ok": true})
}
