package routes

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/conn"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/clash/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupSelectedProxyTest(t *testing.T, started bool) string {
	t.Helper()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	content := `{
		"proxy": [
			{"id": "proxy-a", "name": "Proxy A", "type": "http", "server": "10.8.0.1", "port": 8082},
			{"id": "proxy-b", "name": "Proxy B", "type": "http", "server": "10.8.0.2", "port": 8083},
			{"id": "proxy-bad", "name": "Broken", "type": "invalid-type", "server": "10.8.0.3", "port": 8084}
		],
		"selected": {"proxy": "proxy-a", "rule": "proxy_all"},
		"setting": {},
		"rules": []
	}`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))

	origPath, origPathErr := configuration.GetConfigFilePath()
	origIsStarted := selectedManagerIsStarted
	origNotify := selectedNotifyManual
	origSelectedProxyId := conn.GetSelectedProxyId()
	origProxy, origProxyErr := conn.GetProxy(constants.PolicyProxy)

	proxyA, err := adapter.ParseProxy(map[string]any{
		"id": "proxy-a", "name": "Proxy A", "type": "http", "server": "10.8.0.1", "port": 8082,
	})
	require.NoError(t, err)
	conn.UpdateProxyWithId(proxyA, "proxy-a")

	t.Cleanup(func() {
		if origPathErr == nil {
			configuration.SetConfigFilePath(origPath)
		}
		selectedManagerIsStarted = origIsStarted
		selectedNotifyManual = origNotify
		if origProxyErr == nil && origProxy != nil {
			conn.UpdateProxyWithId(origProxy, origSelectedProxyId)
		} else {
			conn.UpdateSelectedProxyId(origSelectedProxyId)
		}
	})

	configuration.SetConfigFilePath(cfgPath)
	selectedManagerIsStarted = func() bool { return started }
	selectedNotifyManual = func(string, string) {}
	return cfgPath
}

func postSelectProxy(id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewBufferString(`{"id":"`+id+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	setProxySelectedId(rec, req)
	return rec
}

func TestSetProxySelectedId_UpdatesSelectedProxyId(t *testing.T) {
	setupSelectedProxyTest(t, true)

	rec := postSelectProxy("proxy-b")

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "proxy-b", conn.GetSelectedProxyId())

	activeProxy, err := conn.GetProxy(constants.PolicyProxy)
	require.NoError(t, err)
	assert.Equal(t, "10.8.0.2:8083", activeProxy.Addr())

	persisted, err := configuration.GetSelectedId("proxy")
	require.NoError(t, err)
	assert.Equal(t, "proxy-b", persisted)
}

func TestSetProxySelectedId_WhenStoppedDoesNotMutateLiveConn(t *testing.T) {
	setupSelectedProxyTest(t, false)

	rec := postSelectProxy("proxy-b")

	require.Equal(t, http.StatusNoContent, rec.Code)
	persisted, err := configuration.GetSelectedId("proxy")
	require.NoError(t, err)
	assert.Equal(t, "proxy-b", persisted)

	// Live conn state must remain unchanged while manager is stopped.
	assert.Equal(t, "proxy-a", conn.GetSelectedProxyId())
	activeProxy, err := conn.GetProxy(constants.PolicyProxy)
	require.NoError(t, err)
	assert.Equal(t, "10.8.0.1:8082", activeProxy.Addr())
}

func TestSetProxySelectedId_InvalidProxyDoesNotCorruptConfigOrConn(t *testing.T) {
	setupSelectedProxyTest(t, true)

	for _, badID := range []string{"does-not-exist", "proxy-bad"} {
		rec := postSelectProxy(badID)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "id=%s", badID)

		persisted, err := configuration.GetSelectedId("proxy")
		require.NoError(t, err)
		assert.Equal(t, "proxy-a", persisted, "config.json must remain unchanged on failed switch (%s)", badID)

		assert.Equal(t, "proxy-a", conn.GetSelectedProxyId())
		activeProxy, err := conn.GetProxy(constants.PolicyProxy)
		require.NoError(t, err)
		assert.Equal(t, "10.8.0.1:8082", activeProxy.Addr())
	}
}

func TestSetProxySelectedId_ConcurrentSwitchesStayConsistent(t *testing.T) {
	setupSelectedProxyTest(t, true)

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		id := "proxy-a"
		if i%2 == 1 {
			id = "proxy-b"
		}
		go func(target string) {
			defer wg.Done()
			rec := postSelectProxy(target)
			assert.Equal(t, http.StatusNoContent, rec.Code)
		}(id)
	}
	wg.Wait()

	finalID := conn.GetSelectedProxyId()
	activeProxy, err := conn.GetProxy(constants.PolicyProxy)
	require.NoError(t, err)
	persisted, err := configuration.GetSelectedId("proxy")
	require.NoError(t, err)

	assert.Equal(t, persisted, finalID, "live selectedProxyId must match persisted config")
	if finalID == "proxy-a" {
		assert.Equal(t, "10.8.0.1:8082", activeProxy.Addr())
	} else {
		require.Equal(t, "proxy-b", finalID)
		assert.Equal(t, "10.8.0.2:8083", activeProxy.Addr())
	}
}
