package pac

import (
	"testing"
)

// TestFetchAndParse_ValidPAC verifies that a well-formed PAC file is parsed correctly.
func TestParse_ValidPAC(t *testing.T) {
	// Minimal PAC: DIRECT for internal, PROXY for everything else
	pac := `function FindProxyForURL(url, host) {
		if (shExpMatch(host, "*.internal.corp")) return "DIRECT";
		if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
		return "PROXY 10.8.0.1:8082";
	}`

	rules, err := Parse(pac)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("expected at least one rule")
	}

	// Verify DIRECT rules were extracted
	directCount := 0
	for _, r := range rules {
		if r.Policy == "DIRECT" {
			directCount++
		}
	}
	if directCount == 0 {
		t.Errorf("expected DIRECT rules, got none. rules: %+v", rules)
	}
	t.Logf("parsed %d rules (%d DIRECT)", len(rules), directCount)
}

// TestParse_EmptyPAC verifies that a minimal PAC doesn't crash.
func TestParse_EmptyPAC(t *testing.T) {
	rules, err := Parse(`function FindProxyForURL(url, host) { return "DIRECT"; }`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("minimal PAC: %d rules", len(rules))
}

// TestClear_ResetsActiveRules verifies Clear() removes all active rules.
func TestClear_ResetsActiveRules(t *testing.T) {
	// Inject fake rules
	activeMu.Lock()
	activeRules = []Rule{{Type: "DOMAIN", Payload: "test.corp", Policy: "DIRECT"}}
	activeMu.Unlock()

	Clear()

	rules := GetActiveRules()
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after Clear(), got %d", len(rules))
	}
}

// TestGetActiveRules_ThreadSafe verifies concurrent access doesn't race.
func TestGetActiveRules_ThreadSafe(t *testing.T) {
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			activeMu.Lock()
			activeRules = []Rule{{Type: "DOMAIN", Payload: "corp.internal", Policy: "DIRECT"}}
			activeMu.Unlock()
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		_ = GetActiveRules()
	}
	<-done
}
