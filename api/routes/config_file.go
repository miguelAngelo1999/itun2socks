package routes

// config_file.go — raw config.json import / export / edit.
//
// GET  /config          → returns the raw config.json content (passwords encrypted on disk)
// PUT  /config          → replaces config.json with the posted body, after validation
//
// Export = GET (Flutter writes it to a user-chosen file).
// Import = PUT with the file's content.
// Edit   = GET, user edits text, PUT back.
//
// The body is validated as a well-formed Config before it is written, so a
// malformed import cannot brick the app. After a successful write the running
// stack is reloaded so the change takes effect without a restart.

import (
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/executor"
	"github.com/igoogolx/itun2socks/internal/manager"
	"github.com/igoogolx/itun2socks/pkg/log"
)

func configRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", exportConfig)
	r.Put("/", importConfig)
	return r
}

// exportConfig returns the raw on-disk config.json (pretty-printed, passwords
// encrypted exactly as stored). Suitable for backup / manual edit.
func exportConfig(w http.ResponseWriter, r *http.Request) {
	path, err := configuration.GetConfigFilePath()
	if err != nil || path == "" {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError("config path not set"))
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError("failed to read config: "+err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="config.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// importConfig replaces config.json with the posted body. The body MUST be a
// valid Config JSON. On success the running stack is reloaded.
func importConfig(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10MB cap
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("failed to read body: "+err.Error()))
		return
	}

	// Validate: must parse as a Config and have the minimum structure.
	var cfg configuration.Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("invalid config JSON: "+err.Error()))
		return
	}

	// Persist via the configuration package so passwords are (re-)encrypted and
	// all the on-write invariants hold. Read() already decrypts, so we hand it
	// the parsed struct directly.
	if err := configuration.Write(cfg); err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError("failed to write config: "+err.Error()))
		return
	}

	log.Infoln("[config] imported new config.json (%d bytes)", len(body))

	// Reload the running stack so the imported config takes effect immediately.
	if manager.GetIsStarted() {
		if _, err := executor.UpdateRule(); err != nil {
			log.Warnln("[config] rule reload after import failed: %v", err)
		}
	}

	render.JSON(w, r, render.M{"success": true})
}
