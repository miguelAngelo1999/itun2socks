// Package blackbox records timestamped incident events for post-mortem diagnosis.
//
// When something goes wrong — proxy auth rejected, all connections failing,
// credential expiry, failover — the blackbox captures the event with full context
// so a developer can read back what happened without guessing from interleaved
// debug logs.
//
// Events are persisted to a ring-buffer JSON file (blackbox.json, max 500 entries).
// The Flutter app can read it via GET /blackbox, and scripts can parse it.
package blackbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// Event is a single blackbox entry.
type Event struct {
	Time    string `json:"time"`
	Type    string `json:"type"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

const maxEvents = 500

var (
	mu     sync.Mutex
	events []Event
	path   string
)

func init() {
	// Will be set properly once homeDir is known via Init().
	events = make([]Event, 0, maxEvents)
}

// Init sets the storage path and loads any existing events from disk.
func Init() {
	mu.Lock()
	defer mu.Unlock()

	dir := constants.Path.HomeDir()
	if dir == "" {
		return
	}
	path = filepath.Join(dir, "blackbox.json")

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &events)
	if len(events) > maxEvents {
		events = events[len(events)-maxEvents:]
	}
}

// Record adds an event to the blackbox.
func Record(eventType, message string, data ...any) {
	mu.Lock()
	defer mu.Unlock()

	var d any
	if len(data) > 0 {
		d = data[0]
	}

	e := Event{
		Time:    time.Now().Format(time.RFC3339),
		Type:    eventType,
		Message: message,
		Data:    d,
	}

	events = append(events, e)
	if len(events) > maxEvents {
		events = events[len(events)-maxEvents:]
	}

	log.Infoln("[blackbox] %s: %s", eventType, message)
	persist()
}

// Events returns all recorded events (newest last).
func Events() []Event {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Event, len(events))
	copy(out, events)
	return out
}

// Since returns events after the given time.
func Since(t time.Time) []Event {
	mu.Lock()
	defer mu.Unlock()
	var out []Event
	for _, e := range events {
		parsed, err := time.Parse(time.RFC3339, e.Time)
		if err == nil && parsed.After(t) {
			out = append(out, e)
		}
	}
	return out
}

func persist() {
	if path == "" {
		return
	}
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o644)
}

// ── Convenience recorders for common incidents ──────────────────────────────

func ProxyConnectFailed(proxyId, proxyName, addr, reason string) {
	Record("proxy-connect-failed", fmt.Sprintf("%s (%s) at %s: %s", proxyName, proxyId[:8], addr, reason), map[string]string{
		"proxyId": proxyId, "proxyName": proxyName, "addr": addr, "reason": reason,
	})
}

func ProxyAuthFailed(proxyId, proxyName, addr string, statusCode int) {
	Record("proxy-auth-failed", fmt.Sprintf("%s at %s returned %d", proxyName, addr, statusCode), map[string]any{
		"proxyId": proxyId, "proxyName": proxyName, "addr": addr, "statusCode": statusCode,
	})
}

func CredentialExpired(proxyIds []string) {
	Record("credential-expired", fmt.Sprintf("expired: %v", proxyIds), map[string]any{
		"proxyIds": proxyIds,
	})
}

// NotifyAuthFailed is set by the API layer. The health-check calls it when the
// selected proxy returns 407 (auth no longer valid), so the UI can prompt the
// user to retype the password. Lives here as a hook to avoid an import cycle
// (blackbox must not import configuration/api).
var NotifyAuthFailed func()

// Auth-failure latch. When the upstream proxy rejects the user's credentials
// with 407, we must (a) tell the UI exactly once, and (b) STOP re-attempting
// the upstream CONNECT on every subsequent request (which would hammer the
// upstream with a known-bad password). The latch is checked on the data path
// (conn.NewTcpConn) to fail those dials fast until the user saves new creds —
// which restarts the manager and clears the latch.
var (
	authLatchMu     sync.Mutex
	authLatched     bool
	authNotifiedAt  time.Time
)

// ReportAuthFailed records an upstream 407 on the data path. It sets the latch
// and notifies the UI, but debounces the notification so a burst of failing
// requests only prompts the user once (not once per request). Safe to call
// from many connection goroutines concurrently.
func ReportAuthFailed(proxyAddr string) {
	authLatchMu.Lock()
	firstTime := !authLatched
	authLatched = true
	// Debounce the UI notification to at most once per 30s.
	notify := firstTime || time.Since(authNotifiedAt) > 30*time.Second
	if notify {
		authNotifiedAt = time.Now()
	}
	authLatchMu.Unlock()

	if firstTime {
		Record("proxy-auth-rejected", "upstream 407 on data path from "+proxyAddr, nil)
	}
	if notify && NotifyAuthFailed != nil {
		NotifyAuthFailed()
	}
}

// IsAuthLatched reports whether the selected proxy's credentials were rejected
// by the upstream and not yet corrected. The data path uses this to fail fast
// instead of retrying a known-bad password.
func IsAuthLatched() bool {
	authLatchMu.Lock()
	defer authLatchMu.Unlock()
	return authLatched
}

// ClearAuthLatch resets the latch. Called when the manager (re)starts — e.g.
// after the user saves new credentials, which restarts the tunnel.
func ClearAuthLatch() {
	authLatchMu.Lock()
	authLatched = false
	authNotifiedAt = time.Time{}
	authLatchMu.Unlock()
}

func FailoverAttempt(fromId, toId, toName string, success bool) {
	Record("failover", fmt.Sprintf("from %s to %s (%s) success=%v", fromId[:8], toId[:8], toName, success), map[string]any{
		"fromId": fromId, "toId": toId, "toName": toName, "success": success,
	})
}

func ManagerStarted() {
	Record("manager-started", "proxy manager started", nil)
}

func ManagerStopped(reason string) {
	Record("manager-stopped", reason, nil)
}

func ConnectivityLost(reason string) {
	Record("connectivity-lost", reason, nil)
}

func ConnectivityRestored() {
	Record("connectivity-restored", "internet reachable again", nil)
}
