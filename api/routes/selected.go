package routes

import (
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	configuration2 "github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/conn"
	"github.com/igoogolx/itun2socks/internal/executor"
	"github.com/igoogolx/itun2socks/internal/manager"
	"github.com/igoogolx/itun2socks/internal/tunnel/statistic"
	"github.com/igoogolx/itun2socks/pkg/clash/adapter"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
)

func selectedRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/rule", setRuleSelectedId)
	r.Post("/proxy", setProxySelectedId)
	return r
}

func proxyNameFromConfig(id string) string {
	proxies, err := configuration2.GetProxies()
	if err != nil {
		return id
	}
	return proxyNameFromID(id, proxies)
}

func setRuleSelectedId(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	ruleSelectedId := req["id"]
	if err := configuration2.SetSelectedId("rule", ruleSelectedId); err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	if manager.GetIsStarted() {
		_, err := executor.UpdateRule()
		statistic.DefaultManager.CloseAllConnections()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, NewError(err.Error()))
			return
		}
	}

	render.NoContent(w, r)
}

var (
	selectedProxyMu          sync.Mutex
	selectedManagerIsStarted = manager.GetIsStarted
	selectedNotifyManual     = func(proxyID, proxyName string) {
		go switchCtrl.NotifyManualSelect(proxyID, proxyName)
	}
)

func setProxySelectedId(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	proxySelectedId := req["id"]

	selectedProxyMu.Lock()
	defer selectedProxyMu.Unlock()

	started := selectedManagerIsStarted()
	var parsedProxy C.Proxy
	var resolvedId string
	if started {
		// Validate and parse before mutating config.json so invalid requests
		// cannot leave config.json and the live dialer out of sync.
		rawProxy, err := configuration2.GetProxy(proxySelectedId)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		parsedProxy, err = adapter.ParseProxy(rawProxy)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if id, ok := rawProxy["id"].(string); ok && id != "" {
			resolvedId = id
		} else {
			resolvedId = proxySelectedId
		}
	}

	if err := configuration2.SetSelectedId("proxy", proxySelectedId); err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	if started {
		conn.UpdateProxyWithId(parsedProxy, resolvedId)
	}

	// Notify the auto-switch controller that the user made a manual selection.
	// This sets a 10-min suppression hold so auto-switch doesn't override it.
	selectedNotifyManual(proxySelectedId, proxyNameFromConfig(proxySelectedId))

	render.NoContent(w, r)
}
