package routes

import (
	"net"
	"os/exec"
	"strings"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/igoogolx/itun2socks/internal/balancer"
	configuration2 "github.com/igoogolx/itun2socks/internal/configuration"
)

func settingRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getSetting)
	r.Get("/interfaces", getInterfaces)
	r.Get("/load-balance", getLoadBalanceStatus)
	r.Get("/config-file-dir-path", getConfigDirPath)
	r.Get("/executable-path", getExecutablePath)
	r.Put("/", setSetting)
	r.Put("/reset-config", resetConfig)
	return r
}

func getInterfaces(w http.ResponseWriter, r *http.Request) {
	interfaces, err := net.Interfaces()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}

	// Build friendly name map from networksetup on macOS
	friendlyNames := map[string]string{}
	if out, err := exec.Command("networksetup", "-listallhardwareports").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		var currentName string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Hardware Port:") {
				currentName = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
			} else if strings.HasPrefix(line, "Device:") && currentName != "" {
				device := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
				friendlyNames[device] = currentName
				currentName = ""
			}
		}
	}

	// Enrich interfaces with friendly names, filtering to useful ones only:
	// must be Up, non-loopback, and have at least one non-loopback IPv4 address.
	type enrichedIface struct {
		net.Interface
		FriendlyName string `json:"FriendlyName,omitempty"`
	}
	enriched := make([]enrichedIface, 0, len(interfaces))
	for _, iface := range interfaces {
		// Must be up and not loopback
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// Must have at least one routable IPv4 address
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		hasIPv4 := false
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				hasIPv4 = true
				break
			}
		}
		if !hasIPv4 {
			continue
		}
		enriched = append(enriched, enrichedIface{
			Interface:    iface,
			FriendlyName: friendlyNames[iface.Name],
		})
	}

	render.JSON(w, r, render.M{
		"interfaces": enriched,
	})
}

func getLoadBalanceStatus(w http.ResponseWriter, r *http.Request) {
	interfaces, healthy, next, strategy, enabled := balancer.GetStatus()
	render.JSON(w, r, render.M{
		"enabled":    enabled,
		"interfaces": interfaces,
		"healthy":    healthy,
		"next":       next,
		"strategy":   strategy,
	})
}

func getSetting(w http.ResponseWriter, r *http.Request) {
	setting, err := configuration2.GetSetting()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	render.JSON(w, r, render.M{
		"setting": setting,
	})
}

func setSetting(w http.ResponseWriter, r *http.Request) {
	var req configuration2.SettingCfg
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	err := configuration2.SetSetting(req)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func getConfigDirPath(w http.ResponseWriter, r *http.Request) {
	configFilePath, err := configuration2.GetConfigFilePath()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	dirPath := filepath.Dir(configFilePath)
	render.JSON(w, r, render.M{
		"path": dirPath,
	})
}

func getExecutablePath(w http.ResponseWriter, r *http.Request) {
	executablePath, err := os.Executable()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, NewError(err.Error()))
		return
	}
	render.JSON(w, r, render.M{
		"path": executablePath,
	})
}

func resetConfig(w http.ResponseWriter, r *http.Request) {
	err := configuration2.Reset()
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	render.NoContent(w, r)
}
