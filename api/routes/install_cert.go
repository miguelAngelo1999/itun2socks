package routes

import (
	"net/http"
	"os"
	"os/exec"
	"runtime"

	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/manager"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/sysproxy"
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
	//   2. Set trust settings in the admin domain (-d) into System.keychain.
	//      lux_core runs as root, so this directly updates the system trust settings
	//      without requiring a GUI authentication dialog.
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

		// Step 2: set trust in the admin domain (-d) into System.keychain.
		// lux_core runs as root, so this directly updates the system trust settings
		// without requiring a GUI authentication prompt.
		trustCmd := exec.Command("security", "add-trusted-cert",
			"-d",
			"-r", "trustRoot",
			"-k", "/Library/Keychains/System.keychain",
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

	// Refresh the Node/Electron CA bundle right away so apps launched from now
	// on trust the new CA, without waiting for the next connect toggle. Only
	// while connected: the bundle path is set in the GUI environment, which is
	// cleared on disconnect.
	if manager.GetIsStarted() {
		sysproxy.ExportCACertsAndSetEnv()
	}

	// Add to in-memory extra roots so subsequent /proxies/check-cert calls
	// immediately trust this certificate without waiting for a core restart.
	AddExtraRoot([]byte(req.PEM))

	log.Infoln("[install-cert] certificate installed successfully")
	render.JSON(w, r, render.M{"success": true})
}
