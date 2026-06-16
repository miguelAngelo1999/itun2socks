package routes

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/mitm"
)

// sslInspectionRouter registers all /ssl-inspection sub-routes.
func sslInspectionRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/settings", getSslInspectionSettings)
	r.Put("/settings", putSslInspectionSettings)
	r.Get("/ca/pem", getSslCAPem)
	r.Get("/ca/der", getSslCADer)
	r.Get("/inspection-list", getInspectionList)
	r.Put("/inspection-list", addInspectionEntry)
	r.Delete("/inspection-list", deleteInspectionEntry)
	r.Post("/inspection-list/toggle", toggleInspectionEntry)
	r.Get("/bypass-list", getBypassList)
	return r
}

// GET /ssl-inspection/settings
func getSslInspectionSettings(w http.ResponseWriter, r *http.Request) {
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

ca := mitm.GetGlobalCA()
if ca != nil {
resp["caFingerprint"] = ca.Fingerprint()
resp["caGeneratedAt"] = ca.GeneratedAt().UTC().Format("2006-01-02T15:04:05Z")
}

render.JSON(w, r, resp)
}

// PUT /ssl-inspection/settings
func putSslInspectionSettings(w http.ResponseWriter, r *http.Request) {
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

// If enabling and the CA singleton is not yet loaded, trigger initialisation.
if req.Enabled && mitm.GetGlobalCA() == nil {
configFilePath, err := configuration.GetConfigFilePath()
if err == nil && configFilePath != "" {
configDir := filepath.Dir(configFilePath)
_, _ = mitm.GetOrInitCA(configDir)
}
}

render.NoContent(w, r)
}

// GET /ssl-inspection/ca/pem
func getSslCAPem(w http.ResponseWriter, r *http.Request) {
ca := mitm.GetGlobalCA()
if ca == nil {
render.Status(r, http.StatusServiceUnavailable)
render.JSON(w, r, NewError("CA not loaded — enable SSL inspection first"))
return
}
pemBytes := ca.CertPEM()
if len(pemBytes) == 0 {
render.Status(r, http.StatusServiceUnavailable)
render.JSON(w, r, NewError("CA certificate not available"))
return
}
w.Header().Set("Content-Type", "application/x-pem-file")
w.Header().Set("Content-Disposition", `attachment; filename=lux-ca.crt`)
_, _ = w.Write(pemBytes)
}

// GET /ssl-inspection/ca/der
func getSslCADer(w http.ResponseWriter, r *http.Request) {
ca := mitm.GetGlobalCA()
if ca == nil {
render.Status(r, http.StatusServiceUnavailable)
render.JSON(w, r, NewError("CA not loaded — enable SSL inspection first"))
return
}
der := ca.CertDER()
if len(der) == 0 {
render.Status(r, http.StatusServiceUnavailable)
render.JSON(w, r, NewError("CA certificate not available"))
return
}
w.Header().Set("Content-Type", "application/pkix-cert")
_, _ = w.Write(der)
}

// GET /ssl-inspection/inspection-list
func getInspectionList(w http.ResponseWriter, r *http.Request) {
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

// PUT /ssl-inspection/inspection-list
func addInspectionEntry(w http.ResponseWriter, r *http.Request) {
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
reloadInspectionList()
render.NoContent(w, r)
}

// DELETE /ssl-inspection/inspection-list
func deleteInspectionEntry(w http.ResponseWriter, r *http.Request) {
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
reloadInspectionList()
render.NoContent(w, r)
}

// POST /ssl-inspection/inspection-list/toggle
func toggleInspectionEntry(w http.ResponseWriter, r *http.Request) {
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
reloadInspectionList()
render.NoContent(w, r)
}

// GET /ssl-inspection/bypass-list
func getBypassList(w http.ResponseWriter, r *http.Request) {
patterns := mitm.GetBypassList()
render.JSON(w, r, render.M{"patterns": patterns})
}

// reloadInspectionList synchronises the persisted config into the in-memory
// InspectionList singleton, if one has been registered via SetGlobalInterceptor.
func reloadInspectionList() {
interceptor := mitm.GetGlobalInterceptor()
if interceptor == nil {
return
}
entries, err := configuration.GetInspectionList()
if err != nil {
return
}
list := interceptor.InspectionList()
if list == nil {
return
}
// Convert configuration entries to mitm entries.
mitmEntries := make([]mitm.InspectionListEntry, len(entries))
for i, e := range entries {
mitmEntries[i] = mitm.InspectionListEntry{
Pattern: e.Pattern,
Enabled: e.Enabled,
}
}
list.LoadFrom(mitmEntries)
}

type certInfoDTO struct {
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotBefore   string `json:"notBefore"`
	NotAfter    string `json:"notAfter"`
	Fingerprint string `json:"fingerprint"`
	IsCA        bool   `json:"isCA"`
}

func buildCertInfo(cert *x509.Certificate) certInfoDTO {
	fp := sha256.Sum256(cert.Raw)
	fpHex := hex.EncodeToString(fp[:])
	formatted := ""
	for i := 0; i < len(fpHex); i += 2 {
		if i > 0 {
			formatted += ":"
		}
		formatted += fpHex[i : i+2]
	}
	return certInfoDTO{
		Subject:     cert.Subject.CommonName,
		Issuer:      cert.Issuer.CommonName,
		NotBefore:   cert.NotBefore.Format(time.RFC3339),
		NotAfter:    cert.NotAfter.Format(time.RFC3339),
		Fingerprint: formatted,
		IsCA:        cert.IsCA,
	}
}
