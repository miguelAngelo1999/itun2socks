package routes

import (
	"net/http"
	"os"
	"os/exec"
	"runtime"

	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// installCert receives a PEM certificate and installs it to the system trust store.
// lux_core runs elevated on both platforms, so no extra prompt is needed.
//
// POST /proxies/install-cert
// Body: {"pem": "-----BEGIN CERTIFICATE-----\n..."}
func installCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PEM string `json:"pem"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("invalid request body"))
		return
	}

	if req.PEM == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("pem is required"))
		return
	}

	// Write PEM to temp file
	tmpFile, err := os.CreateTemp("", "lux_cert_*.pem")
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError("failed to create temp file: "+err.Error()))
		return
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(req.PEM); err != nil {
		tmpFile.Close()
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError("failed to write cert: "+err.Error()))
		return
	}
	tmpFile.Close()

	// Install to the system trust store.
	// macOS: security add-trusted-cert (lux_core runs as root).
	// Windows: certutil -addstore Root (lux_core runs elevated via LuxApp task).
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("certutil", "-addstore", "-f", "Root", tmpFile.Name())
	} else {
		cmd = exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot",
			"-k", "/Library/Keychains/System.keychain", tmpFile.Name())
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorln("[install-cert] cert install failed: %v, output: %s", err, string(output))
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError("cert install failed: "+string(output)))
		return
	}

	log.Infoln("[install-cert] certificate installed successfully")

	// On macOS, flush the trust evaluation cache so that subsequent calls to
	// x509.SystemCertPool() (including our own check-cert probe) pick up the
	// newly-installed root without needing a process restart.
	// `security verify-cert` forces a SecTrustEvaluate pass which invalidates
	// the per-process trust anchor cache.
	if runtime.GOOS == "darwin" {
		flush := exec.Command("security", "verify-cert", "-c", tmpFile.Name())
		// Ignore exit code — the cert may not yet be a trusted anchor for all
		// policies, but the side-effect (cache flush) still occurs.
		_ = flush.Run()
	}

	render.JSON(w, r, render.M{"success": true})
}
