package routes

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSwitchEnv struct {
	mu             sync.Mutex
	proxies        []map[string]any
	selectedID     string
	managerStarted bool

	proxyAlive       map[string]bool
	directResult     DirectProbeResult
	probeProxyCalls  atomic.Int32
	probeDirectCalls atomic.Int32
	onProbeDirect    func()

	startCalls        atomic.Int32
	closeCalls        atomic.Int32
	directModeCalls   atomic.Int32
	corpModeCalls     atomic.Int32
	corpCloseConnFlag bool
	failCorpModeErr   error
	lastCorpProxyID   string
	inDirectRouting   bool
	broadcastEvents   []map[string]any
}

func newSingleProxyEnv() *fakeSwitchEnv {
	// Matches c.p/mac & c.p/win configs: single corporate proxy, NO "type":"direct" entry.
	return &fakeSwitchEnv{
		proxies: []map[string]any{
			{
				"id":     "house-1",
				"name":   "Congregatio Proxy",
				"type":   "http",
				"server": "10.8.0.1",
				"port":   float64(8082),
			},
		},
		selectedID:     "house-1",
		managerStarted: true,
		proxyAlive:     map[string]bool{"house-1": false},
		directResult:   DirectProbeResult{State: noInternet},
	}
}

func (e *fakeSwitchEnv) newController(enabled bool) *switchController {
	return &switchController{
		enabled:               enabled,
		state:                 stateCorporate,
		activeProxyID:         e.selectedID,
		activeProxyName:       "Congregatio Proxy",
		lastUserProxyID:       e.selectedID,
		lastUserProxyName:     "Congregatio Proxy",
		preferredBackInterval: 25 * time.Millisecond,
		captivePollInterval:   15 * time.Millisecond,
		captiveMaxDuration:    500 * time.Millisecond,
		captiveCooldown:       200 * time.Millisecond,

		getProxiesFn: func() ([]map[string]any, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.proxies, nil
		},
		getProxyPasswordFn: func(string) string { return "" },
		getSelectedProxyIDFn: func() string {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.selectedID
		},
		isManagerStartedFn: func() bool {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.managerStarted
		},
		startManagerFn: func() error {
			e.startCalls.Add(1)
			e.mu.Lock()
			e.managerStarted = true
			e.inDirectRouting = false
			e.mu.Unlock()
			return nil
		},
		closeManagerFn: func() error {
			e.closeCalls.Add(1)
			e.mu.Lock()
			e.managerStarted = false
			e.mu.Unlock()
			return nil
		},
		applyDirectModeFn: func() error {
			e.directModeCalls.Add(1)
			e.mu.Lock()
			e.inDirectRouting = true
			e.mu.Unlock()
			return nil
		},
		applyCorporateModeFn: func(proxyID string, closeExisting bool) error {
			e.corpModeCalls.Add(1)
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.failCorpModeErr != nil {
				return e.failCorpModeErr
			}
			e.lastCorpProxyID = proxyID
			e.corpCloseConnFlag = closeExisting
			e.inDirectRouting = false
			return nil
		},
		probeProxiesFn: func(candidates []ProxyCandidate) []ProbeResult {
			e.probeProxyCalls.Add(1)
			e.mu.Lock()
			defer e.mu.Unlock()
			out := make([]ProbeResult, len(candidates))
			for i, cand := range candidates {
				out[i] = ProbeResult{
					ProxyID: cand.ID,
					Alive:   e.proxyAlive[cand.ID],
					Latency: 5 * time.Millisecond,
				}
			}
			return out
		},
		probeDirectFn: func() DirectProbeResult {
			e.probeDirectCalls.Add(1)
			e.mu.Lock()
			hook := e.onProbeDirect
			e.mu.Unlock()
			if hook != nil {
				hook()
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.directResult
		},
		broadcastFn: func(payload map[string]any) {
			e.mu.Lock()
			e.broadcastEvents = append(e.broadcastEvents, payload)
			e.mu.Unlock()
		},
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", desc)
}

func TestSwitchController_CaptivePortalFailClosed_AutoSwitchOff(t *testing.T) {
	env := newSingleProxyEnv()
	env.directResult = DirectProbeResult{
		State:       captivePortal,
		RedirectURL: "http://airport.wifi/login",
	}
	ctrl := env.newController(false) // autoSwitchEnabled == false (default institutional policy)
	defer ctrl.NotifyManualStop()

	ctrl.Trigger("connectivity-change")

	waitForCondition(t, time.Second, "enter stateCaptivePortal", func() bool {
		return ctrl.Status().State == stateCaptivePortal
	})

	st := ctrl.Status()
	if st.CaptivePortalURL != "http://airport.wifi/login" {
		t.Fatalf("got CaptivePortalURL=%q, want airport login url", st.CaptivePortalURL)
	}
	if env.closeCalls.Load() != 1 {
		t.Fatalf("expected closeManager called once, got %d", env.closeCalls.Load())
	}

	env.mu.Lock()
	if len(env.broadcastEvents) == 0 || env.broadcastEvents[0]["state"] != "captive_portal" {
		t.Fatalf("expected captive_portal broadcast, got %+v", env.broadcastEvents)
	}
	if env.broadcastEvents[0]["portalUrl"] != "http://airport.wifi/login" {
		t.Fatalf("expected portalUrl in broadcast, got %+v", env.broadcastEvents[0])
	}
	env.mu.Unlock()

	// User completes sign-in -> probeDirect returns directOK, house proxy still dead.
	proxyCallsBeforeClear := env.probeProxyCalls.Load()
	env.mu.Lock()
	env.directResult = DirectProbeResult{State: directOK}
	env.mu.Unlock()

	// Must resume FAIL-CLOSED on configured corporate proxy (NOT direct!).
	waitForCondition(t, time.Second, "fail-closed resume to stateCorporate", func() bool {
		return ctrl.Status().State == stateCorporate
	})

	if env.startCalls.Load() != 1 {
		t.Fatalf("expected startManager called once, got %d", env.startCalls.Load())
	}
	if env.directModeCalls.Load() != 0 {
		t.Fatalf("autoSwitchEnabled=false must NOT enter direct mode (got %d calls)", env.directModeCalls.Load())
	}
	if env.corpModeCalls.Load() != 1 || env.lastCorpProxyID != "house-1" {
		t.Fatalf("expected fail-closed applyCorporateMode(house-1), got calls=%d id=%q",
			env.corpModeCalls.Load(), env.lastCorpProxyID)
	}
	if env.probeProxyCalls.Load() <= proxyCallsBeforeClear {
		t.Fatalf("expected configured proxies to be re-probed before deciding resume mode")
	}
}

func TestSwitchController_CaptivePortalToDirectToCorporate_AutoSwitchOn(t *testing.T) {
	env := newSingleProxyEnv() // NO "type":"direct" proxy entry in config!
	env.directResult = DirectProbeResult{
		State:       captivePortal,
		RedirectURL: "http://hotel.local/portal",
	}
	ctrl := env.newController(true)
	defer ctrl.NotifyManualStop()

	// 1. Corporate -> Captive Portal.
	ctrl.Trigger("wake")
	waitForCondition(t, time.Second, "enter stateCaptivePortal", func() bool {
		return ctrl.Status().State == stateCaptivePortal
	})
	if env.closeCalls.Load() != 1 {
		t.Fatalf("expected TUN pause via closeManager, got %d", env.closeCalls.Load())
	}

	// 2. Portal clears -> directOK -> stateDirect.
	env.mu.Lock()
	env.directResult = DirectProbeResult{State: directOK}
	env.mu.Unlock()

	waitForCondition(t, time.Second, "transition captive_portal -> stateDirect", func() bool {
		return ctrl.Status().State == stateDirect
	})
	if env.startCalls.Load() != 1 || env.directModeCalls.Load() != 1 {
		t.Fatalf("expected startManager=1, directMode=1, got %d / %d", env.startCalls.Load(), env.directModeCalls.Load())
	}

	// 3. House LAN proxy comes back -> preferredBackTicker restores stateCorporate
	//    and closes lingering direct connections (closeExisting=true).
	env.mu.Lock()
	env.proxyAlive["house-1"] = true
	env.mu.Unlock()

	waitForCondition(t, time.Second, "preferredBackTicker restores stateCorporate", func() bool {
		return ctrl.Status().State == stateCorporate
	})

	env.mu.Lock()
	closedDirectConns := env.corpCloseConnFlag
	stillDirect := env.inDirectRouting
	env.mu.Unlock()
	if !closedDirectConns {
		t.Fatalf("expected closeExisting=true when transitioning from direct back to corporate")
	}
	if stillDirect {
		t.Fatalf("expected inDirectRouting=false after returning to corporate proxy")
	}
}

func TestSwitchController_CaptivePortalSafetyTimeoutAndCooldown(t *testing.T) {
	env := newSingleProxyEnv()
	env.directResult = DirectProbeResult{
		State:       captivePortal,
		RedirectURL: "http://never-signed-in.local/",
	}
	ctrl := env.newController(false)
	ctrl.captivePollInterval = 20 * time.Millisecond
	ctrl.captiveMaxDuration = 80 * time.Millisecond
	ctrl.captiveCooldown = 250 * time.Millisecond
	defer ctrl.NotifyManualStop()

	ctrl.Trigger("connectivity-change")
	waitForCondition(t, time.Second, "enter stateCaptivePortal", func() bool {
		return ctrl.Status().State == stateCaptivePortal
	})

	// Safety timeout must auto-exit and resume Lux fail-closed.
	waitForCondition(t, time.Second, "auto-exit captive_portal on safety timeout", func() bool {
		return ctrl.Status().State == stateCorporate
	})
	if env.startCalls.Load() != 1 {
		t.Fatalf("expected fail-closed resume after timeout, got startCalls=%d", env.startCalls.Load())
	}

	// Immediate automatic re-trigger during cooldown must NOT re-enter captive_portal
	// (prevents hostile portal infinite pause/resume bypass loop — Opus H4).
	callsBefore := env.probeDirectCalls.Load()
	ctrl.Trigger("connectivity-change")
	waitForCondition(t, time.Second, "cooldown probe finishes", func() bool {
		return !ctrl.Status().Probing && env.probeDirectCalls.Load() > callsBefore
	})
	if ctrl.Status().State == stateCaptivePortal {
		t.Fatalf("automatic trigger must NOT re-enter captive_portal during safety cooldown")
	}

	// Explicit manual trigger overrides cooldown and enters captive_portal again.
	ctrl.Trigger("manual")
	waitForCondition(t, time.Second, "manual trigger overrides cooldown", func() bool {
		return ctrl.Status().State == stateCaptivePortal
	})
}

func TestSwitchController_ReachableHouseProxyNeverEntersCaptiveOrDirect(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		env := newSingleProxyEnv()
		env.proxyAlive["house-1"] = true
		env.directResult = DirectProbeResult{State: captivePortal}
		ctrl := env.newController(enabled)
		defer ctrl.NotifyManualStop()

		ctrl.Trigger("connectivity-change")
		waitForCondition(t, time.Second, "probe cycle completes", func() bool {
			return !ctrl.Status().Probing && env.probeProxyCalls.Load() >= 1
		})

		if ctrl.Status().State != stateCorporate {
			t.Fatalf("enabled=%v: got state=%s, want stateCorporate", enabled, ctrl.Status().State)
		}
		if env.probeDirectCalls.Load() != 0 || env.closeCalls.Load() != 0 || env.directModeCalls.Load() != 0 {
			t.Fatalf("enabled=%v: reachable proxy must never probe direct, pause TUN, or switch direct", enabled)
		}
	}
}

func TestSwitchController_NoInternetRecoveryTickerRestoresCorporate(t *testing.T) {
	env := newSingleProxyEnv()
	env.directResult = DirectProbeResult{State: noInternet}
	ctrl := env.newController(true)
	defer ctrl.NotifyManualStop()

	ctrl.Trigger("connectivity-change")
	waitForCondition(t, time.Second, "enter stateNoInternet", func() bool {
		return ctrl.Status().State == stateNoInternet
	})

	env.mu.Lock()
	env.proxyAlive["house-1"] = true
	env.mu.Unlock()

	waitForCondition(t, time.Second, "recover from stateNoInternet to stateCorporate", func() bool {
		return ctrl.Status().State == stateCorporate
	})
}

func TestSwitchController_ManualStopCancelsCaptivePortalAutoResume(t *testing.T) {
	env := newSingleProxyEnv()
	env.directResult = DirectProbeResult{State: captivePortal}
	ctrl := env.newController(false)
	ctrl.captivePollInterval = 15 * time.Millisecond
	ctrl.captiveMaxDuration = 80 * time.Millisecond

	ctrl.Trigger("connectivity-change")
	waitForCondition(t, time.Second, "enter stateCaptivePortal", func() bool {
		return ctrl.Status().State == stateCaptivePortal
	})

	if err := ctrl.ManualStop(); err != nil {
		t.Fatalf("ManualStop: %v", err)
	}
	if ctrl.Status().State != stateIdle {
		t.Fatalf("expected stateIdle after ManualStop, got %s", ctrl.Status().State)
	}

	env.mu.Lock()
	env.directResult = DirectProbeResult{State: directOK}
	env.mu.Unlock()
	time.Sleep(130 * time.Millisecond)

	if env.startCalls.Load() != 0 {
		t.Fatalf("ManualStop must prevent captive-portal auto-resume, got startCalls=%d", env.startCalls.Load())
	}
}

// Regression test (Opus Critical #1): disabling auto-switch while probeDirect is
// in-flight must abort the stale cycle and never apply direct mode.
func TestSwitchController_InFlightDisablePreventsDirectLeak(t *testing.T) {
	env := newSingleProxyEnv()
	env.directResult = DirectProbeResult{State: directOK}

	inProbe := make(chan struct{})
	releaseProbe := make(chan struct{})
	env.onProbeDirect = func() {
		close(inProbe)
		<-releaseProbe
	}

	ctrl := env.newController(true)
	defer ctrl.NotifyManualStop()

	ctrl.Trigger("connectivity-change")
	<-inProbe

	// User disables auto-switch mid-probe!
	ctrl.SetEnabled(false)
	close(releaseProbe)

	waitForCondition(t, time.Second, "in-flight probe finishes", func() bool {
		return !ctrl.Status().Probing
	})

	if env.directModeCalls.Load() != 0 {
		t.Fatalf("in-flight cycle leaked into direct mode after SetEnabled(false)!")
	}
	if ctrl.Status().State == stateDirect {
		t.Fatalf("state must not become stateDirect after SetEnabled(false)")
	}
}

// Regression test (Opus High #2): failed corporate restore on SetEnabled(false)
// from stateDirect must fail closed by closing the manager instead of leaving
// unproxied direct traffic active.
func TestSwitchController_FailedCorporateRestoreFailsClosed(t *testing.T) {
	env := newSingleProxyEnv()
	env.directResult = DirectProbeResult{State: directOK}
	ctrl := env.newController(true)
	defer ctrl.NotifyManualStop()

	ctrl.Trigger("connectivity-change")
	waitForCondition(t, time.Second, "enter stateDirect", func() bool {
		return ctrl.Status().State == stateDirect
	})

	env.mu.Lock()
	env.failCorpModeErr = errors.New("corrupted proxy entry")
	env.mu.Unlock()

	ctrl.SetEnabled(false)

	if env.closeCalls.Load() != 1 {
		t.Fatalf("expected fail-closed closeManager() on failed restore, got %d", env.closeCalls.Load())
	}
	if ctrl.Status().State != stateNoInternet {
		t.Fatalf("expected stateNoInternet after fail-closed restore failure, got %s", ctrl.Status().State)
	}
}

// Regression test (Opus Medium #5 & #7): mid-probe Trigger coalesces into a
// rerun instead of dropping, and restores the user's preferred proxy first.
func TestSwitchController_MidProbeTriggerCoalescesAndPrefersLastUserProxy(t *testing.T) {
	env := newSingleProxyEnv()
	env.proxies = append(env.proxies, map[string]any{
		"id":     "house-2",
		"name":   "Preferred House Proxy",
		"type":   "http",
		"server": "10.8.0.2",
		"port":   float64(8082),
	})
	env.proxyAlive["house-2"] = false
	env.directResult = DirectProbeResult{State: directOK}

	firstProbeEntered := make(chan struct{})
	releaseFirstProbe := make(chan struct{})
	var firstDone atomic.Bool
	env.onProbeDirect = func() {
		if firstDone.CompareAndSwap(false, true) {
			close(firstProbeEntered)
			<-releaseFirstProbe
		}
	}

	ctrl := env.newController(true)
	ctrl.lastUserProxyID = "house-2"
	ctrl.lastUserProxyName = "Preferred House Proxy"
	defer ctrl.NotifyManualStop()

	// First trigger sees both proxies down and blocks in probeDirect.
	ctrl.Trigger("connectivity-change")
	<-firstProbeEntered

	// While first probe is in flight, both proxies come up and a second trigger fires!
	env.mu.Lock()
	env.proxyAlive["house-1"] = true
	env.proxyAlive["house-2"] = true
	env.mu.Unlock()
	ctrl.Trigger("connectivity-change")

	close(releaseFirstProbe)

	// Coalesced rerun must pick up house-2 (lastUserProxyID) over house-1.
	waitForCondition(t, time.Second, "coalesced rerun restores preferred house-2", func() bool {
		st := ctrl.Status()
		return !st.Probing && st.State == stateCorporate && st.ActiveProxyID == "house-2"
	})
}
