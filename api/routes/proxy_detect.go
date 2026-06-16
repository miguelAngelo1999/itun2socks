package routes

import (
	"net/http"

	"github.com/go-chi/render"
)

// DetectedProxy holds information about a discovered upstream proxy.
type DetectedProxy struct {
	// Source describes how the proxy was discovered.
	// Possible values: "dhcp_option252", "wpad_dns", "pac", "manual", "env"
	Source string `json:"source"`

	// Host is the proxy hostname or IP address.
	Host string `json:"host"`

	// Port is the proxy port as a string (e.g. "3128").
	Port string `json:"port"`

	// PacURL is the PAC file URL, if that was the discovery mechanism.
	PacURL string `json:"pacUrl,omitempty"`

	// RequiresAuth is true when a 407 Proxy-Authentication-Required was
	// returned during the probe — meaning the proxy needs credentials.
	RequiresAuth bool `json:"requiresAuth"`

	// Error is non-empty when discovery succeeded but probing failed.
	Error string `json:"error,omitempty"`
}

// ProxyDetectResult is the top-level response from GET /proxies/detect.
type ProxyDetectResult struct {
	// Detected is true when at least one upstream proxy was found.
	Detected bool `json:"detected"`

	// Proxies is the list of discovered proxies (may be empty).
	Proxies []DetectedProxy `json:"proxies"`

	// Error is non-empty when the detection itself failed (not a per-proxy
	// error).
	Error string `json:"error,omitempty"`
}

// handleDetectProxy is the HTTP handler for GET /proxies/detect.
// The platform-specific detectNetworkProxy() is in proxy_detect_{os}.go.
func handleDetectProxy(w http.ResponseWriter, r *http.Request) {
	result := detectNetworkProxy()
	render.JSON(w, r, result)
}
