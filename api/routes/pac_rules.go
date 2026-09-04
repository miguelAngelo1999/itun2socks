package routes

import (
	"net/http"

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
}

// getPACRules fetches the PAC script for a proxy and returns its parsed rules.
//
// GET /proxies/:proxyId/pac-rules
//
// Returns {"pacUrl": "...", "rules": [...], "error": "..."}.
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
			"pacUrl": "",
			"rules":  []PACRuleItem{},
		})
		return
	}

	rules, err := pac.FetchAndParse(pacURL)
	if err != nil {
		render.JSON(w, r, render.M{
			"pacUrl": pacURL,
			"rules":  []PACRuleItem{},
			"error":  err.Error(),
		})
		return
	}

	items := make([]PACRuleItem, 0, len(rules))
	for _, rule := range rules {
		items = append(items, PACRuleItem{
			RuleType: rule.Type,
			Payload:  rule.Payload,
			Policy:   rule.Policy,
		})
	}

	render.JSON(w, r, render.M{
		"pacUrl": pacURL,
		"rules":  items,
	})
}
