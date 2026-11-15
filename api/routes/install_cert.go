package routes

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/manager"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/sysproxy"
)

// installCert receives a PEM certificate (or fetches it from host) and installs it to the system trust store.
// Target Store: Cert:\LocalMachine\Root (Windows) or System.keychain (macOS).
//
// POST /proxies/install-cert
// Body: {"pem": "-----BEGIN CERTIFICATE-----\n..."} or {"host": "10.8.0.1"}
func installCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PEM  string `json:"pem"`
		Host string `json:"host"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("invalid request body"))
		return
	}

	if req.PEM == "" && req.Host != "" {
		ca, pemBytes, err := fetchDirectCA(req.Host)
		if err != nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, NewError(fmt.Sprintf("Could not reach the proxy certificate endpoint at http://%s/root-ca. Verify your local network connection.", req.Host)))
			return
		}
		req.PEM = string(pemBytes)
		_ = ca
	}

	if req.PEM == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, NewError("pem or host is required"))
		return
	}

	// Parse certificate to allow thumbprint verification
	var cert *x509.Certificate
	block, _ := pem.Decode([]byte(req.PEM))
	if block != nil {
		cert, _ = x509.ParseCertificate(block.Bytes)
	}

	if runtime.GOOS == "windows" {
		tmpPath := filepath.Join(os.TempDir(), "upstream-proxy-ca.crt")
		if err := os.WriteFile(tmpPath, []byte(req.PEM), 0644); err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, NewError("failed to write cert: "+err.Error()))
			return
		}
		defer os.Remove(tmpPath)

		// Target Store: Cert:\LocalMachine\Root
		// Try PowerShell Import-Certificate first
		psCmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
			fmt.Sprintf("Import-Certificate -FilePath '%s' -CertStoreLocation Cert:\\LocalMachine\\Root -ErrorAction Stop", tmpPath))
		psOut, psErr := psCmd.CombinedOutput()
		if psErr != nil {
			log.Infoln("[install-cert] PowerShell Import-Certificate note: %v (%s), trying certutil fallback", psErr, string(psOut))
			certutilCmd := exec.Command("certutil.exe", "-addstore", "-f", "Root", tmpPath)
			cuOut, cuErr := certutilCmd.CombinedOutput()
			if cuErr != nil {
				log.Errorln("[install-cert] windows install failed: ps=%s, certutil=%s", string(psOut), string(cuOut))
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, NewError("cert install failed: "+string(cuOut)))
				return
			}
		}

		// Verify the certificate is present in Cert:\LocalMachine\Root before declaring success
		if cert != nil && !isCertInSystemStore(cert) {
			log.Errorln("[install-cert] cert verification in Cert:\\LocalMachine\\Root failed")
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, NewError("verification failed: certificate not found in Cert:\\LocalMachine\\Root"))
			return
		}
	} else {
		// macOS
		tmpPath := "/tmp/upstream-proxy-ca.crt"
		if err := os.WriteFile(tmpPath, []byte(req.PEM), 0644); err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, NewError("failed to write cert: "+err.Error()))
			return
		}
		defer os.Remove(tmpPath)

		// Step 1: add to System.keychain (physical storage)
		addCmd := exec.Command("/usr/bin/security", "add-certificates",
			"-k", "/Library/Keychains/System.keychain", tmpPath)
		if out, err := addCmd.CombinedOutput(); err != nil {
			log.Infoln("[install-cert] add-certificates note: %s", string(out))
		}

		// Step 2: set trust in the admin domain (-d) into System.keychain
		trustCmd := exec.Command("/usr/bin/security", "add-trusted-cert",
			"-d",
			"-r", "trustRoot",
			"-k", "/Library/Keychains/System.keychain",
			tmpPath)
		out, err := trustCmd.CombinedOutput()
		if err != nil {
			log.Errorln("[install-cert] macOS trust settings failed: %v, output: %s", err, string(out))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, NewError("cert trust failed: "+string(out)))
			return
		}
		log.Infoln("[install-cert] macOS trust settings written, output: %s", string(out))
	}

	// Refresh the Node/Electron CA bundle right away so apps launched from now
	// on trust the new CA, without waiting for the next connect toggle.
	if manager.GetIsStarted() {
		sysproxy.ExportCACertsAndSetEnv()
	}

	// Add to in-memory extra roots so subsequent checks immediately trust this cert
	AddExtraRoot([]byte(req.PEM))

	log.Infoln("[install-cert] certificate installed successfully")
	render.JSON(w, r, render.M{"success": true})
}
