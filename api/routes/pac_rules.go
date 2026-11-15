package routes

import (
	"encoding/json"
	"net"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/pac"
)

// PACRuleItem is a single rule extracted from a PAC script.
type PACRuleItem struct {
	RuleType string `json:"ruleType"` // DOMAIN, DOMAIN-SUFFIX, IP-CIDR
	Payload  string `json:"payload"`  // e.g. "example.com", "10.0.0.0/8"
	Policy   string `json:"policy"`   // DIRECT or PROXY
	Function string `json:"function,omitempty"` // dnsDomainIs, shExpMatch, isInNet
}

// getPACRules fetches the PAC script for a proxy and returns its parsed rules,
// raw script content, and currently resolved upstream directive.
//
// GET /proxies/:proxyId/pac-rules
//
// Returns {"pacUrl": "...", "rawScript": "...", "script": "...", "rules": [...], "upstream": "...", "error": "..."}.
// If the proxy has no pacUrl, returns an empty rules list.
func getPACRules(w http.ResponseWriter, r *http.Request) {
	proxyId := chi.URLParam(r, "proxyId")
	if proxyId == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("proxyId required"))
		return
	}

	proxy, err := configuration.GetProxy(proxyId)
	if err != nil {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, NewError(err.Error()))
		return
	}

	pacURL, _ := proxy["pacUrl"].(string)
	if pacURL == "" {
		render.JSON(w, r, render.M{
			"pacUrl":    "",
			"rawScript": "",
			"script":    "",
			"rules":     []PACRuleItem{},
			"upstream":  "",
		})
		return
	}

	rawScript := pac.DefaultRegistry.GetRawScript(proxyId)
	if rawScript == "" {
		var fetchErr error
		rawScript, fetchErr = pac.Fetch(pacURL)
		if fetchErr != nil {
			render.JSON(w, r, render.M{
				"pacUrl":    pacURL,
				"rawScript": "",
				"script":    "",
				"rules":     []PACRuleItem{},
				"upstream":  "",
				"error":     fetchErr.Error(),
			})
			return
		}
	}

	rules, parseErr := pac.Parse(rawScript)
	if parseErr != nil {
		render.JSON(w, r, render.M{
			"pacUrl":    pacURL,
			"rawScript": rawScript,
			"script":    rawScript,
			"rules":     []PACRuleItem{},
			"upstream":  "",
			"error":     parseErr.Error(),
		})
		return
	}

	items := make([]PACRuleItem, 0, len(rules))
	for _, rule := range rules {
		items = append(items, PACRuleItem{
			RuleType: rule.Type,
			Payload:  rule.Payload,
			Policy:   rule.Policy,
			Function: rule.Function,
		})
	}

	upstream := ""
	host := ""
	if u, err := neturl.Parse(defaultDelayTestUrl); err == nil {
		host = u.Hostname()
	}
	directive, hasPAC, timedOut := pac.DefaultRegistry.EvalDirective(proxyId, defaultDelayTestUrl, host)
	if hasPAC && !timedOut {
		upstream = directive
	} else if rawScript != "" {
		if c, err := pac.Compile(rawScript); err == nil {
			res, to := c.EvalRaw(defaultDelayTestUrl, host)
			if !to && res != "" {
				upstream = res
			}
		}
	}

	render.JSON(w, r, render.M{
		"pacUrl":    pacURL,
		"rawScript": rawScript,
		"script":    rawScript,
		"rules":     items,
		"upstream":  upstream,
	})
}

// testPACUrl evaluates a given URL or hostname against the proxy's PAC script.
//
// POST /proxies/:proxyId/pac-test
// GET  /proxies/:proxyId/pac-test?url=...
func testPACUrl(w http.ResponseWriter, r *http.Request) {
	proxyId := chi.URLParam(r, "proxyId")
	if proxyId == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("proxyId required"))
		return
	}

	targetURL := ""
	if r.Method == http.MethodPost {
		var req struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			targetURL = strings.TrimSpace(req.URL)
		}
	}
	if targetURL == "" {
		targetURL = strings.TrimSpace(r.URL.Query().Get("url"))
	}
	if targetURL == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("url parameter required"))
		return
	}

	fullURL := targetURL
	if !strings.Contains(fullURL, "://") {
		fullURL = "http://" + fullURL
	}
	host := ""
	if u, err := neturl.Parse(fullURL); err == nil {
		host = u.Hostname()
	}
	if host == "" {
		host = targetURL
	}

	directive, hasPAC, timedOut := pac.DefaultRegistry.EvalDirective(proxyId, fullURL, host)
	if !hasPAC {
		proxy, err := configuration.GetProxy(proxyId)
		if err == nil {
			if pacURL, _ := proxy["pacUrl"].(string); pacURL != "" {
				script := pac.DefaultRegistry.GetRawScript(proxyId)
				if script == "" {
					script, _ = pac.Fetch(pacURL)
				}
				if script != "" {
					if c, err := pac.Compile(script); err == nil {
						res, to := c.EvalRaw(fullURL, host)
						if to {
							timedOut = true
						} else {
							directive = res
							hasPAC = true
						}
					}
				}
			}
		}
	}

	if timedOut {
		render.JSON(w, r, render.M{
			"error":     "evaluation timed out",
			"directive": "",
			"action":    "DIRECT",
			"upstream":  "",
		})
		return
	}

	if !hasPAC {
		render.JSON(w, r, render.M{
			"error":     "no active PAC found for proxy",
			"directive": "",
			"action":    "DIRECT",
			"upstream":  "",
		})
		return
	}

	directives := pac.ParseDirectives(directive)
	action := "DIRECT"
	upstream := ""
	if !pac.IsDirectResult(directive) {
		action = "PROXY"
		for _, d := range directives {
			if !d.IsDirect() && d.Host != "" {
				upstream = net.JoinHostPort(d.Host, d.Port)
				break
			}
		}
	}

	render.JSON(w, r, render.M{
		"directive":  directive,
		"action":     action,
		"upstream":   upstream,
		"directives": directives,
	})
}
