package sysproxy

import (
	"net"
	"os/exec"
	"runtime"

	"github.com/igoogolx/itun2socks/pkg/log"
)

func Set(addr string, activeInterface string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if err := SetWebProxy(host, port, activeInterface); err != nil {
		return err
	}
	// Set environment variables so terminal, Node, Go, Docker etc. also use the proxy.
	setEnvProxy(addr)
	return nil
}

func Clear(activeInterface string) error {
	clearEnvProxy()
	return DisableWebProxy(activeInterface)
}

// setEnvProxy injects HTTP_PROXY/HTTPS_PROXY into the GUI session environment.
// On macOS this uses launchctl setenv, which affects all apps launched after this
// point (including new terminal tabs). Existing terminals need to re-read it or
// source their profile.
func setEnvProxy(addr string) {
	if runtime.GOOS != "darwin" {
		return
	}
	url := "http://" + addr
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if err := exec.Command("launchctl", "setenv", key, url).Run(); err != nil {
			log.Debugln("[sysproxy] launchctl setenv %s failed: %v", key, err)
		}
	}
	// Node.js/Electron apps (Antigravity, Kiro, Windsurf, etc.) need these to
	// trust corporate proxy certificates and not reject TLS handshakes.
	_ = exec.Command("launchctl", "setenv", "NODE_EXTRA_CA_CERTS", "/Library/Keychains/System.keychain").Run()
	_ = exec.Command("launchctl", "setenv", "NODE_TLS_REJECT_UNAUTHORIZED", "0").Run()
	_ = exec.Command("launchctl", "setenv", "NODE_OPTIONS", "--use-openssl-ca").Run()
	log.Infoln("[sysproxy] set env proxy to %s + Node TLS vars", url)
}

// clearEnvProxy removes the env vars set by setEnvProxy.
func clearEnvProxy() {
	if runtime.GOOS != "darwin" {
		return
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
		"NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS"} {
		_ = exec.Command("launchctl", "unsetenv", key).Run()
	}
	log.Infoln("[sysproxy] cleared env proxy and Node TLS vars")
}
