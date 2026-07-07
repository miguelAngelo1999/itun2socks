package routes

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/manager"
)

func healthRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getHealth)
	return r
}

type HealthStatus struct {
	OK      bool   `json:"ok"`
	Latency int    `json:"latency"` // ms
	Error   string `json:"error,omitempty"`
}

// getHealth probes actual traffic flow through lux's local proxy port.
// Uses https://www.gstatic.com/generate_204 — the standard connectivity check
// used by Android, Chrome OS, Clash, and Mihomo. Returns empty 204 on success.
//
// The probe goes: this request → lux local port → upstream proxy → internet.
// If any part of that chain is broken, the probe fails.
func getHealth(w http.ResponseWriter, r *http.Request) {
	if !manager.GetIsStarted() {
		render.JSON(w, r, &HealthStatus{OK: false, Error: "not started"})
		return
	}

	// Read local proxy port from config
	config, err := configuration.Read()
	if err != nil {
		render.JSON(w, r, &HealthStatus{OK: false, Error: "config read failed"})
		return
	}
	localPort := config.Setting.Port
	if localPort == 0 {
		localPort = 1090
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", localPort))

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout: 8 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		// Don't follow redirects — captive portals redirect, real connectivity returns 204
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://www.gstatic.com/generate_204", nil)
	req.Header.Set("User-Agent", "lux-health-check/1.0")

	resp, err := client.Do(req)
	latency := int(time.Since(start).Milliseconds())

	if err != nil {
		render.JSON(w, r, &HealthStatus{OK: false, Latency: latency, Error: err.Error()})
		return
	}
	defer resp.Body.Close()

	// 204 = success (Google generate_204)
	// 200 = success (some proxies downgrade 204 to 200)
	// 3xx = captive portal or proxy redirect — considered broken
	// 403 = corporate proxy blocking — considered broken
	// 407 = auth failed — considered broken
	ok := resp.StatusCode == 204 || resp.StatusCode == 200
	errMsg := ""
	if !ok {
		errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	render.JSON(w, r, &HealthStatus{OK: ok, Latency: latency, Error: errMsg})
}
