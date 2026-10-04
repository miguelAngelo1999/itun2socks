//go:build windows

package sysproxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/log"
	"golang.org/x/sys/windows/registry"
)

// Windows broadcasts environment changes to running processes via a
// WM_SETTINGCHANGE message to all top-level windows. New processes (a freshly
// launched cmd, PowerShell, node, pip, git, curl…) inherit the updated
// HKCU\Environment block; already-running shells do not until relaunched.
var (
	user32              = syscall.NewLazyDLL("user32.dll")
	procSendMessageTime = user32.NewProc("SendMessageTimeoutW")
)

const (
	hwndBroadcast   = 0xffff
	wmSettingChange = 0x001A
	smtoAbortIfHung = 0x0002
)

// broadcastEnvChange notifies the shell that HKCU\Environment changed so new
// processes pick up the new proxy variables without a logoff.
func broadcastEnvChange() {
	envPtr, _ := syscall.UTF16PtrFromString("Environment")
	_, _, _ = procSendMessageTime.Call(
		uintptr(hwndBroadcast),
		uintptr(wmSettingChange),
		0,
		uintptr(unsafe.Pointer(envPtr)),
		uintptr(smtoAbortIfHung),
		uintptr(5000),
		0,
	)
}

// exportProxyCACerts dumps the Windows trusted CA stores to a PEM bundle so
// Node.js (which ships its own CA list and ignores the Windows store) can trust
// a corporate proxy's MITM CA via NODE_EXTRA_CA_CERTS. Returns "" on failure.
//
// It enumerates, in BOTH the CurrentUser and LocalMachine locations:
//   - Root     : trusted root CAs (where most installers, incl. lux, place a CA)
//   - CA       : intermediate CAs — some proxy MITM setups install their CA here
//   - AuthRoot : the auto-updated third-party root store
// Scanning all three (not just Root) is what guarantees the proxy's CA is
// captured regardless of which store it landed in. Certs are de-duplicated by
// thumbprint so a cert present in several stores is emitted once.
func exportProxyCACerts() string {
	bundlePath := filepath.Join(constants.Path.HomeDir(), "proxy_ca_bundle.pem")
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0755); err != nil {
		log.Warnln("[sysproxy] exportProxyCACerts: mkdir failed: %v", err)
		return ""
	}

	// PowerShell: walk every (location, store) pair, dedupe by thumbprint, emit
	// base64 PEM for each unique cert.
	ps := `$ErrorActionPreference='SilentlyContinue';` +
		`$seen=@{};$out=@();` +
		`foreach($loc in 'CurrentUser','LocalMachine'){` +
		`  foreach($store in 'Root','CA','AuthRoot'){` +
		`    foreach($c in Get-ChildItem "Cert:\$loc\$store"){` +
		`      if($seen.ContainsKey($c.Thumbprint)){continue};` +
		`      $seen[$c.Thumbprint]=$true;` +
		`      $b=[Convert]::ToBase64String($c.RawData,'InsertLineBreaks');` +
		`      $out += "-----BEGIN CERTIFICATE-----`+"`n"+`$b`+"`n"+`-----END CERTIFICATE-----"` +
		`    }` +
		`  }` +
		`};` +
		`Set-Content -Path '` + bundlePath + `' -Value ($out -join "` + "`n" + `") -Encoding ascii`

	if err := exec.Command("powershell", "-NonInteractive", "-NoProfile", "-Command", ps).Run(); err != nil {
		log.Warnln("[sysproxy] exportProxyCACerts: powershell export failed: %v", err)
		return ""
	}
	if fi, err := os.Stat(bundlePath); err != nil || fi.Size() == 0 {
		log.Warnln("[sysproxy] exportProxyCACerts: empty/missing bundle")
		return ""
	}
	log.Infoln("[sysproxy] exported trusted CAs (Root+CA+AuthRoot) to %s", bundlePath)
	return bundlePath
}

// setEnvProxyPlatform writes the proxy env vars (and NODE_EXTRA_CA_CERTS) into
// the persistent per-user environment (HKCU\Environment) and broadcasts the
// change so CLI tools launched afterwards route through lux.
func setEnvProxyPlatform(addr string) {
	url := "http://" + addr
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE)
	if err != nil {
		log.Warnln("[sysproxy] open HKCU\\Environment: %v", err)
		return
	}
	defer k.Close()

	for _, key := range envProxyVars {
		if err := k.SetStringValue(key, url); err != nil {
			log.Debugln("[sysproxy] set %s: %v", key, err)
		}
	}
	// Never proxy loopback/link-local so lux's own health checks and local
	// services keep working.
	_ = k.SetStringValue("NO_PROXY", "localhost,127.0.0.1,::1")
	_ = k.SetStringValue("no_proxy", "localhost,127.0.0.1,::1")

	if bundlePath := exportProxyCACerts(); bundlePath != "" {
		_ = k.SetStringValue("NODE_EXTRA_CA_CERTS", bundlePath)
		log.Infoln("[sysproxy] NODE_EXTRA_CA_CERTS → %s", bundlePath)
	}

	broadcastEnvChange()
	log.Infoln("[sysproxy] set env proxy to %s", url)
}

// clearEnvProxyPlatform deletes the env vars set by setEnvProxyPlatform and
// broadcasts the change.
func clearEnvProxyPlatform() {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE)
	if err != nil {
		log.Warnln("[sysproxy] open HKCU\\Environment: %v", err)
		return
	}
	defer k.Close()

	keys := append([]string{}, envProxyVars...)
	keys = append(keys,
		"NO_PROXY", "no_proxy",
		"NODE_EXTRA_CA_CERTS",
		"NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS",
	)
	for _, key := range keys {
		if err := k.DeleteValue(key); err != nil && err != registry.ErrNotExist {
			log.Debugln("[sysproxy] delete %s: %v", key, err)
		}
	}

	broadcastEnvChange()
	log.Infoln("[sysproxy] cleared env proxy and Node CA vars")
}
