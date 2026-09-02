package sysproxy

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// exportProxyCACerts exports all trusted CA certificates from the macOS System
// Keychain into a PEM bundle that Node.js can read via NODE_EXTRA_CA_CERTS.
//
// Node.js does not read the macOS keychain — it has its own OpenSSL cert bundle.
// The only official mechanism to add trust is NODE_EXTRA_CA_CERTS pointing at a
// real PEM file. Setting it to the binary .keychain file does nothing.
//
// We use `security find-certificate -a -p` which prints all certs in the given
// keychain as PEM. We combine System + SystemRoots so corporate proxy CAs that
// were added via `security add-trusted-cert` (which Lux's cert installer uses)
// are included.
//
// Returns the path to the written bundle, or "" on failure.
func exportProxyCACerts() string {
	bundlePath := filepath.Join(constants.Path.HomeDir(), "proxy_ca_bundle.pem")

	var buf bytes.Buffer

	for _, keychain := range []string{
		"/Library/Keychains/System.keychain",
		"/System/Library/Keychains/SystemRootCertificates.keychain",
	} {
		out, err := exec.Command("security", "find-certificate", "-a", "-p", keychain).Output()
		if err != nil {
			log.Debugln("[sysproxy] find-certificate %s: %v", keychain, err)
			continue
		}
		buf.Write(out)
	}

	if buf.Len() == 0 {
		log.Warnln("[sysproxy] exportProxyCACerts: no certs found, skipping bundle")
		return ""
	}

	if err := os.MkdirAll(filepath.Dir(bundlePath), 0755); err != nil {
		log.Warnln("[sysproxy] exportProxyCACerts: mkdir failed: %v", err)
		return ""
	}

	if err := os.WriteFile(bundlePath, buf.Bytes(), 0644); err != nil {
		log.Warnln("[sysproxy] exportProxyCACerts: write failed: %v", err)
		return ""
	}

	lines := strings.Count(buf.String(), "BEGIN CERTIFICATE")
	log.Infoln("[sysproxy] exported %d certs to %s", lines, bundlePath)
	return bundlePath
}

func Set(addr string, activeInterface string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if err := SetWebProxy(host, port, activeInterface); err != nil {
		return err
	}
	setEnvProxy(addr)
	return nil
}

func Clear(activeInterface string) error {
	clearEnvProxy()
	return DisableWebProxy(activeInterface)
}

// setEnvProxy injects HTTP_PROXY/HTTPS_PROXY and Node.js TLS vars into the GUI
// session environment via launchctl setenv (macOS only, daemon session).
//
// NODE_EXTRA_CA_CERTS is set to a real PEM bundle exported from the System
// Keychain — not the binary .keychain file, which Node.js cannot read.
// NODE_TLS_REJECT_UNAUTHORIZED and NODE_OPTIONS are intentionally omitted:
// they disable TLS verification globally which is worse than useless once
// the CA cert is properly trusted.
func setEnvProxy(addr string) {
	if runtime.GOOS != "darwin" {
		return
	}
	url := "http://" + addr
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if err := exec.Command("launchctl", "setenv", key, url).Run(); err != nil {
			log.Debugln("[sysproxy] launchctl setenv %s: %v", key, err)
		}
	}

	// Export trusted CA certs to a PEM file and point Node.js at it.
	if bundlePath := exportProxyCACerts(); bundlePath != "" {
		_ = exec.Command("launchctl", "setenv", "NODE_EXTRA_CA_CERTS", bundlePath).Run()
		log.Infoln("[sysproxy] NODE_EXTRA_CA_CERTS → %s", bundlePath)
	}

	log.Infoln("[sysproxy] set env proxy to %s", url)
}

// clearEnvProxy removes the env vars set by setEnvProxy.
func clearEnvProxy() {
	if runtime.GOOS != "darwin" {
		return
	}
	for _, key := range []string{
		"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
		"NODE_EXTRA_CA_CERTS",
		// Legacy: unset even if we stopped setting them, in case a prior version set them
		"NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS",
	} {
		_ = exec.Command("launchctl", "unsetenv", key).Run()
	}
	log.Infoln("[sysproxy] cleared env proxy and Node TLS vars")
}
