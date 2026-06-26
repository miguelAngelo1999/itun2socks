package routes

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/pac"
)

func pacRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/status", getPacStatus)
	r.Post("/apply", applyPac)
	r.Post("/clear", clearPac)
	return r
}

func getPacStatus(w http.ResponseWriter, r *http.Request) {
	rules := pac.GetActiveRules()
	url := pac.GetPacURL()

	ruleStrs := make([]string, len(rules))
	for i, rule := range rules {
		ruleStrs[i] = rule.String()
	}

	render.JSON(w, r, render.M{
		"active":  len(rules) > 0,
		"url":     url,
		"count":   len(rules),
		"rules":   ruleStrs,
		"domains": pac.GetDirectDomains(),
		"cidrs":   pac.GetDirectCIDRs(),
	})
}

func applyPac(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil || req.URL == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("url is required"))
		return
	}

	rules, err := pac.Apply(req.URL)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}

	ruleStrs := make([]string, len(rules))
	for i, rule := range rules {
		ruleStrs[i] = rule.String()
	}

	render.JSON(w, r, render.M{
		"count": len(rules),
		"rules": ruleStrs,
	})
}

func clearPac(w http.ResponseWriter, r *http.Request) {
	pac.Clear()
	render.NoContent(w, r)
}
