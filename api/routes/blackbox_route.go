package routes

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/blackbox"
)

func blackboxRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getBlackbox)
	r.Get("/recent", getRecentBlackbox)
	return r
}

// GET /blackbox — all events
func getBlackbox(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, blackbox.Events())
}

// GET /blackbox/recent — events from the last 30 minutes
func getRecentBlackbox(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-30 * time.Minute)
	render.JSON(w, r, blackbox.Since(since))
}
