package routes

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/mitm"
	ssl "github.com/igoogolx/itun2socks/internal/ssl_inspect"
)

var (
	lastSslCheck  time.Time
	lastSslStatus ssl.BumpStatus
)

// sslInspectRouter registers all /ssl-inspect sub-routes.
// This covers both passive upstream MITM detection and active SSL inspection management.
func sslInspectRouter() chi.Router {
	r := chi.NewRouter()

	// Passive upstream proxy detection
	r.Get("/status", sslInspectStatus)
	r.Get("/cert", sslInspectCert)

	// Active SSL inspection (Lux-generated CA / MITM engine)
	r.Get("/settings", sslInspectGetSettings)
	r.Put("/settings", sslInspectPutSettings)
	r.Get("/ca/pem", sslInspectGetCAPem)
	r.Get("/ca/der", sslInspectGetCADer)
	r.Get("/inspection-list", sslInspectGetInspectionList)
	r.Put("/inspection-list", sslInspectPutInspectionList)
	r.Delete("/inspection-list", sslInspectDeleteInspectionList)
	r.Post("/inspection-list/toggle", sslInspectToggleInspectionList)
	r.Get("/bypass-list", sslInspectGetBypassList)

	return r
}

// ── Passive detection ───────────────────────────────────────────────────────

// sslInspectStatus probes whether an upstream proxy is intercepting HTTPS.
func sslInspectStatus(w http.ResponseWriter, r *http.Request) {
	const minInterval = 30 * time.Second
	if time.Since(lastSslCheck) > minInterval {
		status := ssl.Detect()
		if status.Detected && len(status.InterceptCA) > 0 {
			ssl.Cache(status.InterceptCA)
		}
		lastSslCheck = time.Now()
		lastSslStatus = status
	}

	resp := map[string]interface{}{
		"detected":  lastSslStatus.Detected,
		"checkedAt": lastSslCheck.Format(time.RFC3339),
		"error":     lastSslStatus.Error,
		"hasCert":   len(ssl.PEM()) > 0,
	}

	if der, _ := ssl.Cached(); len(der) > 0 {
		if info := parseSslCertInfo(der); info != nil {
			resp["certInfo"] = info
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// sslInspectCert returns the captured upstream CA cert as PEM.
func sslInspectCert(w http.ResponseWriter, r *http.Request) {
	p := ssl.PEM()
	if len(p) == 0 {
		http.Error(w, "no certificate captured", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="lux_intercept_ca.pem"`)
	_, _ = w.Write(p)
}

// ── Active MITM inspection ─────────────────────────────────────────────────

// sslInspectGetSettings returns the current SSL inspection settings.
func sslInspectGetSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := configuration.GetSslInspectionSettings()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	resp := render.M{
		"enabled":       cfg.Enabled,
		"caFingerprint": nil,
		"caGeneratedAt": nil,
	}
	if ca := mitm.GetGlobalCA(); ca != nil {
		resp["caFingerprint"] = ca.Fingerprint()
		resp["caGeneratedAt"] = ca.GeneratedAt().Format(time.RFC3339)
	}
	render.JSON(w, r, resp)
}

// sslInspectPutSettings enables or disables SSL inspection.
func sslInspectPutSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := configuration.SetSslInspectionEnabled(req.Enabled); err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	if req.Enabled {
		configFilePath, err := configuration.GetConfigFilePath()
		if err == nil && configFilePath != "" {
			configDir := filepath.Dir(configFilePath)
			if _, err := mitm.GetOrInitCA(configDir); err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, NewError("failed to initialise CA: "+err.Error()))
				return
			}
		}
	}
	render.NoContent(w, r)
}

// sslInspectGetCAPem downloads Lux's own Root CA cert as PEM.
func sslInspectGetCAPem(w http.ResponseWriter, r *http.Request) {
	ca := mitm.GetGlobalCA()
	if ca == nil {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, NewError("no CA available — enable SSL inspection first"))
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename=lux-ca.crt`)
	_, _ = w.Write(ca.CertPEM())
}

// sslInspectGetCADer downloads Lux's own Root CA cert in DER format.
func sslInspectGetCADer(w http.ResponseWriter, r *http.Request) {
	ca := mitm.GetGlobalCA()
	if ca == nil {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, NewError("no CA available — enable SSL inspection first"))
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	_, _ = w.Write(ca.CertDER())
}

// sslInspectGetInspectionList returns all inspection list entries.
func sslInspectGetInspectionList(w http.ResponseWriter, r *http.Request) {
	entries, err := configuration.GetInspectionList()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	if entries == nil {
		entries = []configuration.SslInspectionEntry{}
	}
	render.JSON(w, r, render.M{"entries": entries})
}

// sslInspectPutInspectionList adds a new pattern to the inspection list.
func sslInspectPutInspectionList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pattern string `json:"pattern"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil || req.Pattern == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := configuration.AddInspectionEntry(req.Pattern); err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	reloadInterceptorList()
	render.NoContent(w, r)
}

// sslInspectDeleteInspectionList removes a pattern from the inspection list.
func sslInspectDeleteInspectionList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pattern string `json:"pattern"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil || req.Pattern == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := configuration.RemoveInspectionEntry(req.Pattern); err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	reloadInterceptorList()
	render.NoContent(w, r)
}

// sslInspectToggleInspectionList flips the enabled state of an inspection entry.
func sslInspectToggleInspectionList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pattern string `json:"pattern"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil || req.Pattern == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := configuration.ToggleInspectionEntry(req.Pattern); err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	reloadInterceptorList()
	render.NoContent(w, r)
}

// sslInspectGetBypassList returns the hardcoded bypass list.
func sslInspectGetBypassList(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"patterns": mitm.GetBypassList()})
}

// reloadInterceptorList syncs the in-memory InspectionList with the persisted config.
func reloadInterceptorList() {
	interceptor := mitm.GetGlobalInterceptor()
	if interceptor == nil {
		return
	}
	entries, err := configuration.GetInspectionList()
	if err != nil {
		return
	}
	mitmEntries := make([]mitm.InspectionListEntry, len(entries))
	for i, e := range entries {
		mitmEntries[i] = mitm.InspectionListEntry{
			Pattern: e.Pattern,
			Enabled: e.Enabled,
		}
	}
	interceptor.InspectionList().LoadFrom(mitmEntries)
}

// parseSslCertInfo extracts human-readable fields from a DER-encoded certificate.
func parseSslCertInfo(der []byte) interface{} {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	fp := sha256.Sum256(der)
	fpHex := hex.EncodeToString(fp[:])
	formatted := ""
	for i := 0; i < len(fpHex); i += 2 {
		if i > 0 {
			formatted += ":"
		}
		formatted += fpHex[i : i+2]
	}
	org := ""
	if len(cert.Subject.Organization) > 0 {
		org = cert.Subject.Organization[0]
	}
	return map[string]interface{}{
		"subject":           cert.Subject.CommonName,
		"issuer":            cert.Issuer.CommonName,
		"notBefore":         cert.NotBefore.Format("2006-01-02"),
		"notAfter":          cert.NotAfter.Format("2006-01-02"),
		"sha256Fingerprint": formatted,
		"isCA":              cert.IsCA,
		"organizationName":  org,
	}
}
