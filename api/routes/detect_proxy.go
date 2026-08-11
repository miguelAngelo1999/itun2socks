package routes

import (
	"net/http"

	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// DetectedProxy is one PROXY entry extracted from a network's PAC script.
type DetectedProxy struct {
	Host   string `json:"host"`
	Port   string `json:"port"`
	PacURL string `json:"pacUrl"`
}

// detectProxies probes the network for a PAC URL (WPAD via DHCP option 252 on
// macOS, registry AutoConfigURL on Windows), fetches and parses it, and returns
// every PROXY host:port it declares.
//
// POST /proxies/detect
func detectProxies(w http.ResponseWriter, r *http.Request) {
	pacURL := pac.ProbeWPADUrl()
	if pacURL == "" {
		render.Status(r, http.StatusOK)
		render.JSON(w, r, map[string]any{
			"pacUrl":  "",
			"proxies": []DetectedProxy{},
			"message": "No PAC URL advertised on this network (DHCP option 252 / registry AutoConfigURL not set)",
		})
		return
	}

	log.Infoln("[detect-proxy] found PAC URL: %s", pacURL)

	// Extract unique PROXY entries from the parsed rules.
	// Rules from Parse() have Policy "PROXY" with payload as "host:port" style info,
	// but the actual proxy address comes from evaluating the script.
	// Skip the rule-based approach and go straight to JS eval for a known external host.
	js, fetchErr := pac.Fetch(pacURL)
	if fetchErr != nil {
		render.Status(r, http.StatusOK)
		render.JSON(w, r, map[string]any{
			"pacUrl":  pacURL,
			"proxies": []DetectedProxy{},
			"message": "Found PAC URL but could not fetch it: " + fetchErr.Error(),
		})
		return
	}

	compiled, compileErr := pac.Compile(js)
	if compileErr != nil {
		render.Status(r, http.StatusOK)
		render.JSON(w, r, map[string]any{
			"pacUrl":  pacURL,
			"proxies": []DetectedProxy{},
			"message": "Found PAC URL but could not compile it: " + compileErr.Error(),
		})
		return
	}

	// Evaluate against well-known external hosts to discover PROXY directives.
	seen := map[string]bool{}
	var proxies []DetectedProxy
	testHosts := []string{"www.google.com", "www.microsoft.com", "example.com"}
	for _, host := range testHosts {
		result := compiled.Eval("https://"+host+"/", host)
		for _, part := range splitPACResult(result) {
			if len(part) > 6 && part[:6] == "PROXY " {
				addr := part[6:]
				if !seen[addr] {
					seen[addr] = true
					h, p := splitHostPort(addr)
					proxies = append(proxies, DetectedProxy{Host: h, Port: p, PacURL: pacURL})
				}
			}
		}
	}

	render.JSON(w, r, map[string]any{
		"pacUrl":  pacURL,
		"proxies": proxies,
		"message": "",
	})
}

func splitHostPort(addr string) (string, string) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:]
		}
	}
	return addr, "8080"
}

func splitPACResult(result string) []string {
	var parts []string
	for _, s := range split(result, ";") {
		s = trim(s)
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}

func split(s, sep string) []string {
	var result []string
	for {
		i := indexOf(s, sep)
		if i < 0 {
			result = append(result, s)
			break
		}
		result = append(result, s[:i])
		s = s[i+len(sep):]
	}
	return result
}

func indexOf(s, sub string) int {
	for i := range s {
		if i+len(sub) <= len(s) && s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func trim(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
