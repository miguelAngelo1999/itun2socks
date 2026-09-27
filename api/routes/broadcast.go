package routes

import (
	"encoding/json"

	"github.com/igoogolx/itun2socks/internal/blackbox"
	"github.com/igoogolx/itun2socks/internal/configuration"
)

// BroadcastEvent sends a JSON event to all connected WebSocket clients on the
// /event channel. The Flutter app listens for these to react in real time.
func BroadcastEvent(eventType string, data any) {
	payload := map[string]any{
		"type": eventType,
		"data": data,
	}
	msg, err := json.Marshal(payload)
	if err != nil {
		return
	}
	hub.broadcast <- msg
}

func init() {
	// Wire the credential-expired notification from internal/configuration back
	// to the WebSocket broadcast, without an import cycle.
	configuration.NotifyCredentialExpired = func(proxyIds []string) {
		BroadcastEvent("credential-expired", map[string]any{
			"proxyIds": proxyIds,
		})
	}
	configuration.NotifyProxySwitch = func(proxyId, proxyName string) {
		BroadcastEvent("proxy-switch", map[string]any{
			"proxyId": proxyId,
			"name":    proxyName,
		})
	}
	// When the health-check sees a 407 from the selected proxy (auth no longer
	// valid), prompt the UI to retype the password for that proxy.
	blackbox.NotifyAuthFailed = func() {
		data, err := configuration.Read()
		if err != nil {
			return
		}
		selected := data.Selected.Proxy
		if selected == "" {
			return
		}
		BroadcastEvent("credential-expired", map[string]any{
			"proxyIds": []string{selected},
		})
	}
}
