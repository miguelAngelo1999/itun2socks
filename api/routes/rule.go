package routes

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/executor"
	"github.com/igoogolx/itun2socks/internal/manager"
	"github.com/igoogolx/itun2socks/internal/tunnel/statistic"
)

func errorsIs(err, target error) bool { return errors.Is(err, target) }

func ruleRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules)

	// Legacy string-based endpoints, retained so the embedded web dashboard
	// keeps working. They resolve the string to a rule id and then delegate.
	r.Put("/customized", addCustomizedRules)
	r.Post("/customized", editCustomizedRule)
	r.Delete("/customized", deleteCustomizedRules)
	r.Post("/customized/reorder", reorderCustomizedRules)
	r.Post("/customized/toggle", toggleCustomizedRule)

	// Id-based endpoints.
	r.Post("/items", createRuleItem)
	r.Patch("/items/{id}", updateRuleItem)
	r.Delete("/items/{id}", deleteRuleItem)
	r.Post("/items/{id}/toggle", toggleRuleItem)
	r.Post("/items/{id}/group", moveRuleItem)
	r.Post("/items/reorder", reorderRuleItems)

	r.Get("/groups", listRuleGroups)
	r.Post("/groups", createRuleGroup)
	r.Patch("/groups/{id}", patchRuleGroup)
	r.Delete("/groups/{id}", deleteRuleGroup)
	r.Post("/groups/reorder", reorderRuleGroups)

	r.Get("/diagnostics", ruleDiagnostics)

	// {id} is last so it cannot swallow the literal paths above.
	r.Get("/{id}", getRuleDetail)
	return r
}

// applyRuleChange reloads the rule engine and drops existing connections so
// traffic is re-evaluated.
//
// Reorder and toggle previously called manager.Close() + manager.Start(), which
// tore down the TUN interface to apply what is only a metadata change. That
// dropped every connection and, on macOS, could leave a stale utun behind.
func applyRuleChange() error {
	if !manager.GetIsStarted() {
		return nil
	}
	if _, err := executor.UpdateRule(); err != nil {
		return err
	}
	statistic.DefaultManager.CloseAllConnections()
	return nil
}

func respondRuleErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case err == nil:
		return
	case errorsIs(err, configuration.ErrRuleNotFound), errorsIs(err, configuration.ErrGroupNotFound):
		render.Status(r, http.StatusNotFound)
	case errorsIs(err, configuration.ErrDuplicateRule), errorsIs(err, configuration.ErrNoConditions):
		render.Status(r, http.StatusBadRequest)
	default:
		render.Status(r, http.StatusInternalServerError)
	}
	render.JSON(w, r, NewError(err.Error()))
}

func getRules(w http.ResponseWriter, r *http.Request) {
	rules, err := configuration.GetRuleIds()
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	selectId, err := configuration.GetSelectedId("rule")
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	render.JSON(w, r, render.M{
		"rules":      rules,
		"selectedId": selectId,
	})
}

// ── Legacy string endpoints ─────────────────────────────────────────────────

func addCustomizedRules(w http.ResponseWriter, r *http.Request) {
	var req map[string][]string
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if len(req["rules"]) == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("invalid rules"))
		return
	}
	if err := configuration.AddCustomizedRule(req["rules"]); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func deleteCustomizedRules(w http.ResponseWriter, r *http.Request) {
	var req map[string][]string
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if len(req["rules"]) == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("invalid rules"))
		return
	}
	if err := configuration.DeleteCustomizedRule(req["rules"]); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func editCustomizedRule(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if len(req["oldRule"]) == 0 || len(req["newRule"]) == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("invalid rules"))
		return
	}
	if err := configuration.EditCustomizedRule(req["oldRule"], req["newRule"]); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func reorderCustomizedRules(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rules []string `json:"rules"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil || len(req.Rules) == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := configuration.ReorderCustomizedRules(req.Rules); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func toggleCustomizedRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rule string `json:"rule"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil || req.Rule == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := configuration.ToggleCustomizedRule(req.Rule); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func getRuleDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if id == "customized" {
		items, err := configuration.GetCustomizedRulesRaw()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, NewError(err.Error()))
			return
		}
		groups, err := configuration.GetRuleGroups()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, NewError(err.Error()))
			return
		}
		render.JSON(w, r, render.M{"items": items, "groups": groups})
		return
	}
	rules, err := configuration.GetBuiltInRules(id)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	render.JSON(w, r, render.M{"items": rules})
}

// ── Id-based endpoints ──────────────────────────────────────────────────────

type ruleItemPayload struct {
	GroupId    string `json:"groupId"`
	Conditions []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"conditions"`
	Policy struct {
		Kind    string `json:"kind"`
		ProxyId string `json:"proxyId"`
	} `json:"policy"`
	Network string `json:"network"`
	Enabled *bool  `json:"enabled"`
}

func (p ruleItemPayload) toItem() configuration.RuleItem {
	conds := make([]configuration.RuleCondition, 0, len(p.Conditions))
	for _, c := range p.Conditions {
		conds = append(conds, configuration.RuleCondition{Type: c.Type, Value: c.Value})
	}
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	return configuration.RuleItem{
		GroupId:    p.GroupId,
		Conditions: conds,
		Policy:     configuration.RulePolicy{Kind: p.Policy.Kind, ProxyId: p.Policy.ProxyId},
		Network:    p.Network,
		Enabled:    enabled,
	}
}

func createRuleItem(w http.ResponseWriter, r *http.Request) {
	var p ruleItemPayload
	if err := render.DecodeJSON(r.Body, &p); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	created, err := configuration.CreateRule(p.toItem())
	if err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.Status(r, http.StatusCreated)
	render.JSON(w, r, created)
}

func updateRuleItem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var p ruleItemPayload
	if err := render.DecodeJSON(r.Body, &p); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := configuration.UpdateRule(id, p.toItem()); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func deleteRuleItem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := configuration.DeleteRule([]string{id}); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func toggleRuleItem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := configuration.ToggleRule(id); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func moveRuleItem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		GroupId string `json:"groupId"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := configuration.MoveRuleToGroup(id, req.GroupId); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func reorderRuleItems(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupId string   `json:"groupId"`
		Ids     []string `json:"ids"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := configuration.ReorderRules(req.GroupId, req.Ids); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

// ── Groups ──────────────────────────────────────────────────────────────────

func listRuleGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := configuration.GetRuleGroups()
	if err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.JSON(w, r, render.M{"groups": groups})
}

func createRuleGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	g, err := configuration.CreateGroup(req.Name)
	if err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.Status(r, http.StatusCreated)
	render.JSON(w, r, g)
}

func patchRuleGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Name   *string `json:"name"`
		Toggle bool    `json:"toggle"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if req.Name != nil {
		if err := configuration.RenameGroup(id, *req.Name); err != nil {
			respondRuleErr(w, r, err)
			return
		}
	}
	if req.Toggle {
		if err := configuration.ToggleGroup(id); err != nil {
			respondRuleErr(w, r, err)
			return
		}
		if err := applyRuleChange(); err != nil {
			respondRuleErr(w, r, err)
			return
		}
	}
	render.NoContent(w, r)
}

func deleteRuleGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := configuration.DeleteGroup(id); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

func reorderRuleGroups(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ids []string `json:"ids"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil || len(req.Ids) == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := configuration.ReorderGroups(req.Ids); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	if err := applyRuleChange(); err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.NoContent(w, r)
}

// ── Diagnostics ─────────────────────────────────────────────────────────────

func ruleDiagnostics(w http.ResponseWriter, r *http.Request) {
	shadowed, err := configuration.ShadowedRules()
	if err != nil {
		respondRuleErr(w, r, err)
		return
	}
	broken, err := configuration.BrokenRules()
	if err != nil {
		respondRuleErr(w, r, err)
		return
	}
	render.JSON(w, r, render.M{"shadowed": shadowed, "broken": broken})
}
