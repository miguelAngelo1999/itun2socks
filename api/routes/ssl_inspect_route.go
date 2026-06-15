package routes

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	ssl "github.com/igoogolx/itun2socks/internal/ssl_inspect"
)

var (
	lastSslCheck  time.Time
	lastSslStatus ssl.BumpStatus
)

type certInfo struct {
	Subject           string `json:"subject"`
	Issuer            string `json:"issuer"`
	OrganizationName  string `json:"organizationName"`
	NotBefore         string `json:"notBefore"`
	NotAfter          string `json:"notAfter"`
	SHA256Fingerprint string `json:"sha256Fingerprint"`
	IsCA              bool   `json:"isCA"`
}

func sslInspectRouter() chi.Router {
	r := chi.NewRouter()
	r.Get("/status", sslInspectStatus)
	r.Get("/cert", sslInspectCert)
	return r
}

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
		if info := parseCertInfo(der); info != nil {
			resp["certInfo"] = info
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

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

func parseCertInfo(der []byte) *certInfo {
	cert, err := x509.ParseCertificate(der)
	if err != nil { return nil }
	fp := sha256.Sum256(der)
	fpHex := hex.EncodeToString(fp[:])
	formatted := ""
	for i := 0; i < len(fpHex); i += 2 {
		if i > 0 { formatted += ":" }
		formatted += fpHex[i : i+2]
	}
	org := ""
	if len(cert.Subject.Organization) > 0 { org = cert.Subject.Organization[0] }
	return &certInfo{
		Subject:           cert.Subject.CommonName,
		Issuer:            cert.Issuer.CommonName,
		OrganizationName:  org,
		NotBefore:         cert.NotBefore.Format("2006-01-02"),
		NotAfter:          cert.NotAfter.Format("2006-01-02"),
		SHA256Fingerprint: formatted,
		IsCA:              cert.IsCA,
	}
}
