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
	// macOS: Two-step process:
	//   1. Add cert to System.keychain (physical storage, requires root — we have it)
	//   2. Set trust settings in the USER domain via `security add-trusted-cert`
	//      WITHOUT -d. The admin/system trust domain (-d) requires a SecAuthorization
	//      dialog even as root on macOS 12+, and silently succeeds without writing
	//      trust settings. The user trust domain works without auth and is read by
	//      Go's x509.SystemCertPool() and by all system TLS consumers.
	// Windows: certutil -addstore Root (lux_core runs elevated via LuxApp task).
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("certutil", "-addstore", "-f", "Root", tmpFile.Name())
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Errorln("[install-cert] cert install failed: %v, output: %s", err, string(output))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, NewError("cert install failed: "+string(output)))
			return
		}
	} else {
		// Step 1: add to System.keychain (root required, which we have)
		addCmd := exec.Command("security", "add-certificates",
			"-k", "/Library/Keychains/System.keychain", tmpFile.Name())
		if out, err := addCmd.CombinedOutput(); err != nil {
			// Non-fatal if cert already exists ("...already installed")
			log.Infoln("[install-cert] add-certificates output: %s", string(out))
		}

		// Step 2: set trust in the user domain — no SecAuthorization needed,
		// works reliably on macOS 12+ even as root. Both ssl and basic policies
		// cover the typical corporate proxy use case.
		trustCmd := exec.Command("security", "add-trusted-cert",
			"-r", "trustRoot",
			"-p", "ssl",
			"-p", "basic",
			tmpFile.Name())
		out, err := trustCmd.CombinedOutput()
		if err != nil {
			log.Errorln("[install-cert] trust settings failed: %v, output: %s", err, string(out))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, NewError("cert trust failed: "+string(out)))
			return
		}
		log.Infoln("[install-cert] trust settings written, output: %s", string(out))
	}

	log.Infoln("[install-cert] certificate installed successfully")
	render.JSON(w, r, render.M{"success": true})
}
