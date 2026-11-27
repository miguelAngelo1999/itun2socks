package routes

import (
	"fmt"
	"testing"
	"time"
)

func newMultiProxyEnv() *fakeSwitchEnv {
	return &fakeSwitchEnv{
		proxies: []map[string]any{
			{"id": "pref", "name": "Preferred Office", "type": "http", "server": "10.8.0.1", "port": float64(8082)},
			{"id": "bak1", "name": "Backup 1", "type": "http", "server": "10.8.0.2", "port": float64(8082)},
			{"id": "bak2", "name": "Backup 2", "type": "socks5", "server": "10.8.0.3", "port": float64(1080)},
			{"id": "pac1", "name": "Fleet PAC", "type": "http", "server": "", "port": float64(0), "pacUrl": "http://wpad/wpad.dat"},
		},
		selectedID:     "pref",
		managerStarted: true,
		proxyAlive: map[string]bool{
			"pref": true,
			"bak1": true,
			"bak2": true,
			"pac1": true,
		},
		directResult: DirectProbeResult{State: directOK},
	}
}

func TestLoadCandidates_IncludesPACOnlyAndSOCKS5(t *testing.T) {
	env := newMultiProxyEnv()
	ctrl := env.newController(true)

	cands, _, err := ctrl.loadCandidates()
	if err != nil {
		t.Fatalf("loadCandidates error: %v", err)
	}
	if len(cands) != 4 {
		t.Fatalf("expected 4 candidates (http + http + socks5 + pac-only), got %d: %+v", len(cands), cands)
	}
	var sawPAC, sawSocks bool
	for _, c := range cands {
		if c.ID == "pac1" && c.Host == "" && c.PacURL == "http://wpad/wpad.dat" {
			sawPAC = true
		}
		if c.ID == "bak2" && c.Type == "socks5" && c.Port == 1080 {
			sawSocks = true
		}
	}
	if !sawPAC {
		t.Error("PAC-only proxy was skipped by loadCandidates")
	}
	if !sawSocks {
		t.Error("SOCKS5 proxy was not loaded with type=socks5")
	}
}

func TestStayConnected_FailoverHysteresisAndSmoothReturn(t *testing.T) {
	env := newMultiProxyEnv()
	health := map[string]ProbeResult{
		"pref": {ProxyID: "pref", Alive: false, Err: fmt.Errorf("timeout")},
		"bak1": {ProxyID: "bak1", Alive: true},
		"bak2": {ProxyID: "bak2", Alive: true},
		"pac1": {ProxyID: "pac1", Alive: true},
	}
	ctrl := env.newController(false)
	ctrl.stayConnected = true
	ctrl.failoverMinDwell = 10 * time.Millisecond
	ctrl.probeHealthFn = func(c ProxyCandidate) ProbeResult {
		r := health[c.ID]
		r.ProxyID = c.ID
		return r
	}

	// 1st failure: anti-flapping — stay on preferred!
	ctrl.runStayConnectedTick()
	if st := ctrl.Status(); st.State != stateCorporate || st.ActiveProxyID != "pref" {
		t.Fatalf("expected to remain on preferred after 1 failure, got %+v", st)
	}

	// 2nd failure: fail over to bak1 WITHOUT closing existing connections!
	ctrl.runStayConnectedTick()
	st := ctrl.Status()
	if st.State != stateFailover || st.ActiveProxyID != "bak1" {
		t.Fatalf("expected failover to bak1 after 2 failures, got %+v", st)
	}
	if env.corpCloseConnFlag {
		t.Fatal("expected closeExisting=false on proxy->backup failover so existing downloads survive")
	}

	// Preferred recovers: 1st healthy check must NOT bounce back yet!
	health["pref"] = ProbeResult{ProxyID: "pref", Alive: true}
	time.Sleep(15 * time.Millisecond) // satisfy min dwell
	ctrl.runStayConnectedTick()
	if st := ctrl.Status(); st.State != stateFailover || st.ActiveProxyID != "bak1" {
		t.Fatalf("expected to stay on bak1 after only 1 healthy check on preferred, got %+v", st)
	}

	// 2nd consecutive healthy check: return smoothly to preferred (closeExisting=false)!
	ctrl.runStayConnectedTick()
	st = ctrl.Status()
	if st.State != stateCorporate || st.ActiveProxyID != "pref" {
		t.Fatalf("expected return to pref after 2 stable healthy checks, got %+v", st)
	}
	if env.corpCloseConnFlag {
		t.Fatal("expected closeExisting=false on return to preferred so existing connections survive")
	}
}

func TestStayConnected_RespectsSelectedBackupModeAndSkips407(t *testing.T) {
	env := newMultiProxyEnv()
	health := map[string]ProbeResult{
		"pref": {ProxyID: "pref", Alive: false},
		"bak1": {ProxyID: "bak1", Alive: true},                     // NOT in selected backup list
		"bak2": {ProxyID: "bak2", Alive: false, AuthRequired: true}, // 407 auth failure — skip!
		"pac1": {ProxyID: "pac1", Alive: true},                     // in selected list and healthy
	}
	ctrl := env.newController(false)
	ctrl.stayConnected = true
	ctrl.SetBackupConfig("selected", []string{"bak2", "pac1"})
	ctrl.probeHealthFn = func(c ProxyCandidate) ProbeResult {
		r := health[c.ID]
		r.ProxyID = c.ID
		return r
	}

	ctrl.runStayConnectedTick()
	ctrl.runStayConnectedTick()

	st := ctrl.Status()
	if st.State != stateFailover || st.ActiveProxyID != "pac1" {
		t.Fatalf("expected failover to skip unselected bak1 and 407 bak2 and choose pac1, got %+v", st)
	}
}

func TestStayConnected_AllDownNeverDisconnectsNeverLeaksDirectWhenHomeOfficeOff(t *testing.T) {
	env := newMultiProxyEnv()
	health := map[string]ProbeResult{
		"pref": {ProxyID: "pref", Alive: false},
		"bak1": {ProxyID: "bak1", Alive: false},
		"bak2": {ProxyID: "bak2", Alive: false},
		"pac1": {ProxyID: "pac1", Alive: false},
	}
	ctrl := env.newController(false) // Auto Home/Office OFF!
	ctrl.stayConnected = true
	ctrl.healthCheckInterval = 30 * time.Second
	ctrl.failoverMaxBackoff = 2 * time.Minute
	ctrl.probeHealthFn = func(c ProxyCandidate) ProbeResult {
		r := health[c.ID]
		r.ProxyID = c.ID
		return r
	}

	// 2 failures -> all down -> stay fail-closed on pref, NEVER direct, NEVER close manager
	ctrl.runStayConnectedTick()
	ctrl.runStayConnectedTick()

	st := ctrl.Status()
	if st.State != stateNoInternet {
		t.Fatalf("expected stateNoInternet when all proxies down, got %+v", st)
	}
	if env.directModeCalls.Load() != 0 {
		t.Fatal("must NEVER switch to direct when Auto Home/Office is OFF")
	}
	if env.closeCalls.Load() != 0 || !env.managerStarted {
		t.Fatal("must NEVER disconnect/stop manager when all proxies are down")
	}
	if d := ctrl.nextHealthDelay(); d != 60*time.Second {
		t.Fatalf("expected backoff step 1 = 60s, got %v", d)
	}

	// Another failed retry caps at 120s
	ctrl.runStayConnectedTick()
	if d := ctrl.nextHealthDelay(); d != 120*time.Second {
		t.Fatalf("expected backoff step 2 = 120s cap, got %v", d)
	}

	// Preferred recovers -> immediately restores corporate and resets backoff!
	health["pref"] = ProbeResult{ProxyID: "pref", Alive: true}
	ctrl.runStayConnectedTick()
	st = ctrl.Status()
	if st.State != stateCorporate || st.ActiveProxyID != "pref" {
		t.Fatalf("expected recovery to pref, got %+v", st)
	}
	if d := ctrl.nextHealthDelay(); d != 30*time.Second {
		t.Fatalf("expected backoff reset to 30s after recovery, got %v", d)
	}
}

func TestStayConnected_ManualSelectAndDisableCancelFailover(t *testing.T) {
	env := newMultiProxyEnv()
	health := map[string]ProbeResult{
		"pref": {ProxyID: "pref", Alive: false},
		"bak1": {ProxyID: "bak1", Alive: true},
	}
	ctrl := env.newController(false)
	ctrl.stayConnected = true
	ctrl.probeHealthFn = func(c ProxyCandidate) ProbeResult {
		r := health[c.ID]
		r.ProxyID = c.ID
		return r
	}

	ctrl.runStayConnectedTick()
	ctrl.runStayConnectedTick()
	if ctrl.Status().State != stateFailover {
		t.Fatalf("expected stateFailover, got %+v", ctrl.Status())
	}

	// Disabling Stay connected smoothly returns to preferred (closeExisting=false)
	ctrl.SetStayConnected(false)
	st := ctrl.Status()
	if st.State != stateCorporate || st.ActiveProxyID != "pref" {
		t.Fatalf("expected return to pref on SetStayConnected(false), got %+v", st)
	}
	if env.corpCloseConnFlag {
		t.Fatal("expected closeExisting=false on disabling Stay connected")
	}

	// Re-enter failover, then manually select bak2 -> resets preferred to bak2
	ctrl.stayConnected = true
	ctrl.runStayConnectedTick()
	ctrl.runStayConnectedTick()
	ctrl.NotifyManualSelect("bak2", "Backup 2")
	st = ctrl.Status()
	if st.State != stateCorporate || st.ActiveProxyID != "bak2" || st.PreferredProxyID != "bak2" {
		t.Fatalf("expected manual select to reset preferred to bak2, got %+v", st)
	}
}
