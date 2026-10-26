// Copyright 2024 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin && !ios

package sysproxy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/log"
)

type ProxyType string

const (
	proxyTypeHTTP  ProxyType = "web"
	proxyTypeHTTPS ProxyType = "secureweb"
	proxyTypeSOCKS ProxyType = "socks"
)

type proxySettings struct {
	host    string
	port    string
	enabled bool
}

// resolveServiceName returns the network service name to hand to networksetup.
//
// networksetup addresses a *service* ("Wi-Fi"), not a device ("en0"), and
// rejects anything else:
//
//	networksetup -setwebproxy en0   -> "** Error: The parameters were not valid." exit 4
//	networksetup -setwebproxy Wi-Fi -> exit 0
//
// Callers pass Setting.HijackDns.NetworkService, which is empty unless the user
// configured DNS hijacking, and may hold a device name. Either way networksetup
// exits 4, which surfaced as the opaque "fail to start the client: exit status 4"
// with no indication of the cause. Resolving it here fixes every caller.
func resolveServiceName(activeInterface string) (string, error) {
	candidate := strings.TrimSpace(activeInterface)

	// A device name is not usable, and neither is an empty string. In both cases
	// derive the service from the current default route.
	if candidate == "" || looksLikeDeviceName(candidate) {
		resolved, err := getActiveNetworkInterface()
		if err != nil {
			return "", fmt.Errorf("cannot determine the active network service: %w", err)
		}
		return resolved, nil
	}
	return candidate, nil
}

// looksLikeDeviceName reports whether s is a BSD interface name such as en0 or
// utun3, rather than a service name such as "Wi-Fi".
func looksLikeDeviceName(s string) bool {
	return regexp.MustCompile(`^(en|utun|bridge|awdl|llw|ap|gif|stf|anpi)\d+$`).MatchString(s)
}

func SetWebProxy(host string, port string, activeInterface string) error {
	service, err := resolveServiceName(activeInterface)
	if err != nil {
		return err
	}

	// Set the web proxy and secure web proxy
	if err := setProxySettings(proxyTypeHTTP, service, host, port); err != nil {
		return fmt.Errorf("set http proxy on %q: %w", service, err)
	}
	if err := setProxySettings(proxyTypeHTTPS, service, host, port); err != nil {
		// revert previous changes
		return fmt.Errorf("set https proxy on %q: %w", service, err)
	}

	// Merge DIRECT-rule bypass entries into this service's exception list so the
	// browser bypasses the proxy for them (e.g. a LAN DVR/camera). Preserves the
	// user's existing bypass entries.
	mergeBypassDomains(service, getExtraBypass())

	return nil
}

// mergeBypassDomains adds entries to a service's proxy bypass list without
// dropping what is already there. networksetup -setproxybypassdomains replaces
// the whole list, so we read the current one first and set the union.
func mergeBypassDomains(service string, extra []string) {
	if len(extra) == 0 {
		return
	}
	out, err := exec.Command("networksetup", "-getproxybypassdomains", service).Output()
	seen := map[string]bool{}
	var merged []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			return
		}
		seen[strings.ToLower(s)] = true
		merged = append(merged, s)
	}
	if err == nil {
		text := string(out)
		if !strings.Contains(strings.ToLower(text), "there aren't any") {
			for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
				add(line)
			}
		}
	}
	for _, e := range extra {
		add(e)
	}
	if len(merged) == 0 {
		return
	}
	args := append([]string{"-setproxybypassdomains", service}, merged...)
	_ = exec.Command("networksetup", args...).Run()
}

func DisableWebProxy(activeInterface string) error {
	service, err := resolveServiceName(activeInterface)
	if err != nil {
		return err
	}

	// disable the web proxy and secure web proxy
	errHTTP := disableProxy(proxyTypeHTTP, service)
	errHTTPs := disableProxy(proxyTypeHTTPS, service)

	return errors.Join(errHTTP, errHTTPs)
}

func SetSOCKSProxy(host string, port string) error {
	// Get the active network interface
	activeInterface, err := getActiveNetworkInterface()
	if err != nil {
		return err
	}

	// Set the SOCKS proxy
	if err := setProxySettings(proxyTypeSOCKS, activeInterface, host, port); err != nil {
		return err
	}

	return nil
}

func DisableSOCKSProxy() error {
	// Get the active network interface
	activeInterface, err := getActiveNetworkInterface()
	if err != nil {
		return err
	}

	// disable the SOCKS proxy
	if err := disableProxy(proxyTypeSOCKS, activeInterface); err != nil {
		return err
	}

	return nil
}

// getActiveNetworkInterface finds the active network interface using shell commands.
// https://keith.github.io/xcode-man-pages/networksetup.8.html#listnetworkserviceorder
func getActiveNetworkInterface() (string, error) {
	//cmd := "networksetup -listnetworkserviceorder | grep `route -n get 0.0.0.0 | grep 'interface' | cut -d ':' -f2` -B 1 | head -n 1 | cut -d ' ' -f2"
	out, err := exec.Command("networksetup", "-listnetworkserviceorder").Output()
	if err != nil {
		return "", err
	}
	inet, err := getDefaultRouteInterface()
	if err != nil {
		return "", err
	}
	return getNetworkServiceName(string(out), inet)
}

// getDefaultRouteInterface gets the default route interface using os command.
// Example output of `route get default` on macOS:
//
//	route to: default
//	destination: default
//	mask: default
//	gateway: 192.168.1.1
//	interface: en0
//	flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
//	recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
//	0         0         0         0         0         0      1500         0
func getDefaultRouteInterface() (string, error) {
	// Execute a command to get the default route
	out, err := exec.Command("route", "get", "default").Output()
	if err != nil {
		return "", err
	}

	// Extract the interface name from the command output
	output := string(out)
	lines := strings.Split(output, "\n")
	var defaultIface string
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "interface:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				defaultIface = fields[1]
				return defaultIface, nil
			}
		}
	}
	return "", fmt.Errorf("failed to get default route interface")
}

// getNetworkServiceName parses the output of networksetup -listnetworkserviceorder to find
// the network service name for a given hardware port (e.g. Wi-Fi for en0)
func getNetworkServiceName(output, hardwarePort string) (string, error) {
	const pattern = `Hardware Port: ([^,]+),`
	// example line: (Hardware Port: Wi-Fi, Device: en0)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, hardwarePort) {
			re := regexp.MustCompile(pattern)
			matches := re.FindStringSubmatch(line)
			if len(matches) >= 2 {
				return matches[1], nil
			}
		}
	}
	return "", fmt.Errorf("failed to find network service name for hardware port %s", hardwarePort)
}

// setProxySettings sets the specified type of proxy on the given network interface.
// https://keith.github.io/xcode-man-pages/networksetup.8.html#getsecurewebproxy
func setProxySettings(p ProxyType, interfaceName string, host string, port string) error {
	switch p {
	case proxyTypeHTTP:
		return exec.Command("networksetup", "-setwebproxy", interfaceName, host, port).Run()
	case proxyTypeHTTPS:
		return exec.Command("networksetup", "-setsecurewebproxy", interfaceName, host, port).Run()
	case proxyTypeSOCKS:
		return exec.Command("networksetup", "-setsocksfirewallproxy", interfaceName, host, port).Run()
	default:
		return fmt.Errorf("unsupported proxy type: %s", p)
	}
}

// disableProxy turns off the specified type of proxy on the given network interface.
// https://keith.github.io/xcode-man-pages/networksetup.8.html#setwebproxystate
func disableProxy(p ProxyType, interfaceName string) error {
	switch p {
	case proxyTypeHTTP:
		return exec.Command("networksetup", "-setwebproxystate", interfaceName, "off").Run()
	case proxyTypeHTTPS:
		return exec.Command("networksetup", "-setsecurewebproxystate", interfaceName, "off").Run()
	case proxyTypeSOCKS:
		return exec.Command("networksetup", "-setsocksfirewallproxystate", interfaceName, "off").Run()
	default:
		return fmt.Errorf("unsupported proxy type: %s", p)
	}
}

func getProxySettings(p ProxyType, interfaceName string) (*proxySettings, error) {
	var output []byte
	var err error
	switch p {
	case proxyTypeHTTP:
		output, err = exec.Command("networksetup", "-getwebproxy", interfaceName).Output()
	case proxyTypeHTTPS:
		output, err = exec.Command("networksetup", "-getsecurewebproxy", interfaceName).Output()
	case proxyTypeSOCKS:
		output, err = exec.Command("networksetup", "-getsocksfirewallproxy", interfaceName).Output()
	default:
		err = fmt.Errorf("unsupported proxy type: %s", p)
	}
	if err != nil {
		return nil, err
	}
	return parseProxySettings(string(output))
}

func parseProxySettings(commandOutput string) (*proxySettings, error) {
	var host, port string
	var enabled bool
	lines := strings.Split(commandOutput, "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmedLine, "Server:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				host = fields[1]
			}
		case strings.HasPrefix(trimmedLine, "Port:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				port = fields[1]
			}
		case strings.HasPrefix(trimmedLine, "Enabled:"):
			switch {
			case strings.Contains(trimmedLine, "Yes"):
				enabled = true
			case strings.Contains(trimmedLine, "No"):
				enabled = false
			default:
				return nil, fmt.Errorf("failed to parse proxy status from output")
			}
		}
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("failed to parse host and port from output")
	}
	return &proxySettings{host: host, port: port, enabled: enabled}, nil
}

func getWebProxy() (host string, port string, enabled bool, err error) {
	activeInterface, err := getActiveNetworkInterface()
	if err != nil {
		return "", "", false, err
	}

	httpSettings, err := getProxySettings(proxyTypeHTTP, activeInterface)
	if err != nil {
		return "", "", false, err
	}

	httpsSettings, err := getProxySettings(proxyTypeHTTPS, activeInterface)
	if err != nil {
		return "", "", false, err
	}

	if httpSettings.host != httpsSettings.host || httpSettings.port != httpsSettings.port {
		return "", "", false, fmt.Errorf("HTTP and HTTPS proxy settings do not match")
	}

	return httpSettings.host, httpSettings.port, httpSettings.enabled, nil
}

func getSOCKSProxy() (host string, port string, enabled bool, err error) {
	activeInterface, err := getActiveNetworkInterface()
	if err != nil {
		return "", "", false, err
	}

	socksSettings, err := getProxySettings(proxyTypeSOCKS, activeInterface)
	if err != nil {
		return "", "", false, err
	}

	return socksSettings.host, socksSettings.port, socksSettings.enabled, nil
}

// ── env-var proxy (macOS) ────────────────────────────────────────────────────

// exportProxyCACerts exports all trusted CA certificates from the macOS System
// Keychain into a PEM bundle that Node.js can read via NODE_EXTRA_CA_CERTS.
//
// Node.js does not read the macOS keychain — it has its own OpenSSL cert bundle.
// The only official mechanism to add trust is NODE_EXTRA_CA_CERTS pointing at a
// real PEM file. Setting it to the binary .keychain file does nothing.
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
	log.Infoln("[sysproxy] exported %d certs to %s", strings.Count(buf.String(), "BEGIN CERTIFICATE"), bundlePath)
	return bundlePath
}

// setEnvProxyPlatform sets HTTP(S)_PROXY/ALL_PROXY and NODE_EXTRA_CA_CERTS in
// the GUI session environment via `launchctl setenv`.
func setEnvProxyPlatform(addr string) {
	url := "http://" + addr
	for _, key := range envProxyVars {
		if err := exec.Command("launchctl", "setenv", key, url).Run(); err != nil {
			log.Debugln("[sysproxy] launchctl setenv %s: %v", key, err)
		}
	}
	setNodeExtraCAPlatform()
	log.Infoln("[sysproxy] set env proxy to %s", url)
}

// setNodeExtraCAPlatform exports ALL macOS system-trusted CAs into the PEM
// bundle and points NODE_EXTRA_CA_CERTS at it. Separated from the proxy-env
// setter so the manager can call it on every mode's connect, not just System.
func setNodeExtraCAPlatform() {
	if bundlePath := exportProxyCACerts(); bundlePath != "" {
		_ = exec.Command("launchctl", "setenv", "NODE_EXTRA_CA_CERTS", bundlePath).Run()
		log.Infoln("[sysproxy] NODE_EXTRA_CA_CERTS → %s", bundlePath)
	}
}

// clearNodeExtraCAPlatform removes NODE_EXTRA_CA_CERTS from the GUI session.
func clearNodeExtraCAPlatform() {
	_ = exec.Command("launchctl", "unsetenv", "NODE_EXTRA_CA_CERTS").Run()
}

// clearEnvProxyPlatform removes the env vars set by setEnvProxyPlatform.
func clearEnvProxyPlatform() {
	keys := append([]string{}, envProxyVars...)
	keys = append(keys,
		"NODE_EXTRA_CA_CERTS",
		// Legacy: unset even if we stopped setting them.
		"NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS",
	)
	for _, key := range keys {
		_ = exec.Command("launchctl", "unsetenv", key).Run()
	}
	log.Infoln("[sysproxy] cleared env proxy and Node TLS vars")
}

// getAllNetworkServices returns all ENABLED network services reported by
// `networksetup -listallnetworkservices` (Wi-Fi, USB Ethernet, Thunderbolt
// Bridge, etc.). Setting the proxy on every service — rather than only the one
// behind the default route — is what makes a USB ethernet adapter (or any
// non-default service) get the proxy too.
//
// The first output line is a header; services prefixed with `*` are disabled
// and skipped. Returns nil on failure so callers fall back to the single-
// interface path.
func getAllNetworkServices() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var services []string
	for i, line := range lines {
		if i == 0 {
			continue // header: "An asterisk (*) denotes that a network service is disabled."
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") {
			continue // blank, or a disabled service
		}
		services = append(services, line)
	}
	return services
}
