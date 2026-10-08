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

//go:build windows

package sysproxy

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type proxySettings struct {
	proxyServer   string
	proxyOverride string
}

var (
	modwininet            = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption = modwininet.NewProc("InternetSetOptionW")
)

// prevPACURL and prevAutoDetect remember the WinINET auto-proxy settings that
// were active before lux set its own proxy. They are restored when the proxy
// is disabled, so browsers regain their original PAC/WPAD behaviour.
var (
	prevPACURL     string
	prevAutoDetect uint32
	prevSaved      bool
)

// prevProxyOverride remembers the user's ProxyOverride (proxy exception list)
// from before lux enabled its proxy, so it can be restored on disable instead
// of being wiped. mergeProxyOverride adds lux's required entries without
// dropping the user's.
var (
	prevProxyOverride string
	prevOverrideSaved bool
)

// mergeProxyOverride returns existing ';'-separated bypass entries with the
// entries in `required` appended, de-duplicated (case-insensitive), order
// preserved (existing first). Either side may be empty.
func mergeProxyOverride(existing, required string) string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		for _, e := range strings.Split(s, ";") {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			k := strings.ToLower(e)
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, e)
		}
	}
	add(existing)
	add(required)
	return strings.Join(out, ";")
}

// prevConnDefault / prevConnLegacy hold the original binary connection-settings
// blobs (DefaultConnectionSettings / SavedLegacySettings) so the WPAD
// "Automatically detect settings" bit can be restored exactly on disable.
var (
	prevConnDefault []byte
	prevConnLegacy  []byte
	prevConnSaved   bool
)

const connectionsKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections`

// clearAutoDetectBit clears bit 0x08 ("Automatically detect settings" / WPAD)
// in a DefaultConnectionSettings-format binary blob and bumps the change
// counter (bytes 4-7, little-endian) so WinINET reloads it.
//
// The blob layout (see MS-format notes / community reverse-engineering):
//   bytes 0-3  : format version (usually 0x46)
//   bytes 4-7  : counter, incremented on every change
//   byte  8    : flags — 0x01 manual proxy, 0x02 PAC script, 0x08 auto-detect
// Returns a NEW slice; the input is not mutated.
func clearAutoDetectBit(blob []byte) []byte {
	if len(blob) < 9 {
		// Malformed/empty. Build a minimal valid blob: version 0x46, counter 1,
		// flags 0x01 (manual proxy on, auto-detect off, no PAC).
		return []byte{0x46, 0, 0, 0, 1, 0, 0, 0, 0x01, 0, 0, 0}
	}
	out := make([]byte, len(blob))
	copy(out, blob)
	// Clear the auto-detect (0x08) and PAC (0x02) bits, keep proxy (0x01) on.
	out[8] &^= 0x08
	// Bump the little-endian counter at bytes 4-7 so the change is honoured.
	ctr := uint32(out[4]) | uint32(out[5])<<8 | uint32(out[6])<<16 | uint32(out[7])<<24
	ctr++
	out[4] = byte(ctr)
	out[5] = byte(ctr >> 8)
	out[6] = byte(ctr >> 16)
	out[7] = byte(ctr >> 24)
	return out
}

// disableWpadAutoDetect rewrites the binary connection-settings blobs to turn
// off "Automatically detect settings". Writing the AutoDetect DWORD alone (as
// older lux builds did) does NOT uncheck the box — WinINET reads the WPAD state
// from bit 0x08 of DefaultConnectionSettings, not from that DWORD. Saves the
// originals into prevConn* for restoration.
func disableWpadAutoDetect() {
	k, err := registry.OpenKey(registry.CURRENT_USER, connectionsKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()

	if !prevConnSaved {
		prevConnDefault, _, _ = k.GetBinaryValue("DefaultConnectionSettings")
		prevConnLegacy, _, _ = k.GetBinaryValue("SavedLegacySettings")
		prevConnSaved = true
	}

	if def, _, e := k.GetBinaryValue("DefaultConnectionSettings"); e == nil && len(def) > 0 {
		_ = k.SetBinaryValue("DefaultConnectionSettings", clearAutoDetectBit(def))
	}
	if leg, _, e := k.GetBinaryValue("SavedLegacySettings"); e == nil && len(leg) > 0 {
		_ = k.SetBinaryValue("SavedLegacySettings", clearAutoDetectBit(leg))
	}
}

// restoreWpadAutoDetect puts the original connection-settings blobs back so the
// user's prior "Automatically detect settings" state returns when lux stops.
func restoreWpadAutoDetect() {
	if !prevConnSaved {
		return
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, connectionsKeyPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if len(prevConnDefault) > 0 {
		_ = k.SetBinaryValue("DefaultConnectionSettings", prevConnDefault)
	}
	if len(prevConnLegacy) > 0 {
		_ = k.SetBinaryValue("SavedLegacySettings", prevConnLegacy)
	}
	prevConnSaved = false
	prevConnDefault = nil
	prevConnLegacy = nil
}

// https://learn.microsoft.com/en-us/windows/win32/wininet/option-flags
// INTERNET_OPTION_SETTINGS_CHANGED: 39
// Notifies the system that the registry settings have been changed so that it verifies the settings on the next call to InternetConnect.
// INTERNET_OPTION_REFRESH: 37
// Causes the proxy data to be reread from the registry for a handle. No buffer is required.
// This option can be used on the HINTERNET handle returned by InternetOpen.
// This is used by InternetSetOption.
const (
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37
)

// getAllNetworkServices returns nil on Windows: the WinINET proxy set by
// SetWebProxy is system-wide (per-user), not per network service, so there is
// nothing to enumerate. Set/Clear fall back to the single call.
func getAllNetworkServices() []string { return nil }

func SetWebProxy(host string, port string, _ string) error {
	// Lux's always-on exceptions plus any derived from the user's DIRECT rules
	// (e.g. a LAN IP-CIDR -> 192.168.61.*), so the browser bypasses the proxy
	// for them. These are MERGED with the user's own ProxyOverride in
	// setProxySettings, never replacing it.
	override := "*.local;<local>"
	for _, e := range getExtraBypass() {
		override += ";" + e
	}
	settings := &proxySettings{
		proxyServer:   net.JoinHostPort(host, port),
		proxyOverride: override,
	}

	return setProxySettings(settings)
}

func DisableWebProxy(_ string) error {
	// disable proxy settings
	return disableProxy()
}

// SetProxy does nothing on windows platforms.
func SetSOCKSProxy(host string, port string) error {
	endpoint := fmt.Sprintf("socks=%s", net.JoinHostPort(host, port))
	settings := &proxySettings{
		proxyServer:   endpoint,
		proxyOverride: "*.local;<local>",
	}

	return setProxySettings(settings)
}

// SetProxy does nothing on windows platforms.
func DisableSOCKSProxy() error {
	return disableProxy()
}

func setProxySettings(settings *proxySettings) error {
	// Before setting our proxy, save and clear the auto-proxy settings.
	// A PAC URL or WPAD auto-detect takes precedence over the manual proxy
	// setting and causes traffic to bypass lux entirely.
	if !prevSaved {
		if k2, e2 := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE|registry.SET_VALUE); e2 == nil {
			prevPACURL, _, _ = k2.GetStringValue("AutoConfigURL")
			{ v64, _, _ := k2.GetIntegerValue("AutoDetect"); prevAutoDetect = uint32(v64) }
			k2.SetStringValue("AutoConfigURL", "")
			k2.SetDWordValue("AutoDetect", 0)
			k2.Close()
			prevSaved = true
		}
	}
	// The AutoDetect DWORD above is not what the Windows proxy UI / WPAD reads;
	// the real "Automatically detect settings" state lives in bit 0x08 of the
	// binary DefaultConnectionSettings blob. Clear it there too, or traffic can
	// still be diverted to a WPAD-discovered proxy and bypass lux.
	disableWpadAutoDetect()
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if err = key.SetStringValue("ProxyServer", settings.proxyServer); err != nil {
		return err
	}
	// Preserve the user's existing proxy exception list. Save the original once
	// so it can be restored on disable, then MERGE our required entries into it
	// rather than replacing it — overwriting ProxyOverride wiped the user's
	// manually-configured bypass hosts on every enable.
	if !prevOverrideSaved {
		prevProxyOverride, _, _ = key.GetStringValue("ProxyOverride")
		prevOverrideSaved = true
	}
	merged := mergeProxyOverride(prevProxyOverride, settings.proxyOverride)
	if err = key.SetStringValue("ProxyOverride", merged); err != nil {
		return err
	}
	// Finally, enable the proxy
	if err = key.SetDWordValue("ProxyEnable", uint32(1)); err != nil {
		return err
	}

	// Refresh the settings
	return notifyWinInetProxySettingsChanged()
}

func disableProxy() error {
	// Restore the auto-proxy settings we saved when the proxy was enabled.
	if prevSaved {
		if k2, e2 := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE); e2 == nil {
			k2.SetStringValue("AutoConfigURL", prevPACURL)
			if prevAutoDetect == 0 { k2.DeleteValue("AutoDetect") } else { k2.SetDWordValue("AutoDetect", prevAutoDetect) }
			k2.Close()
		}
		prevSaved = false
	}
	// Restore the original binary connection-settings blob (and thus the user's
	// prior "Automatically detect settings" state).
	restoreWpadAutoDetect()
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	// Restore the user's original proxy exception list (ProxyOverride) that we
	// merged into on enable, so lux leaves it exactly as it found it.
	if prevOverrideSaved {
		if prevProxyOverride == "" {
			key.DeleteValue("ProxyOverride")
		} else {
			key.SetStringValue("ProxyOverride", prevProxyOverride)
		}
		prevOverrideSaved = false
		prevProxyOverride = ""
	}

	// Set ProxyEnable to 0
	err = key.SetDWordValue("ProxyEnable", 0)
	if err != nil {
		return err
	}

	// Refresh the settings
	return notifyWinInetProxySettingsChanged()
}

// https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetsetoptionw
// internetSetOption sets an Internet option.
func internetSetOption(hInternet uintptr, dwOption int, lpBuffer uintptr, dwBufferLength uint32) error {
	ret, _, lastErr := procInternetSetOption.Call(
		hInternet,
		uintptr(dwOption),
		lpBuffer,
		uintptr(dwBufferLength),
	)
	if ret == 0 {
		return lastErr
	}
	return nil
}

func notifyWinInetProxySettingsChanged() error {
	if err := internetSetOption(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0); err != nil {
		return fmt.Errorf("failed to notify the system that the registry settings have been changed: %w", err)
	}

	if err := internetSetOption(0, INTERNET_OPTION_REFRESH, 0, 0); err != nil {
		return fmt.Errorf("failed to refresh the proxy data from the registry: %w", err)
	}

	return nil
}
func getWebProxy() (host string, port string, enabled bool, err error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return "", "", false, err
	}
	defer key.Close()

	address, _, err := key.GetStringValue("ProxyServer")
	if err != nil {
		return "", "", false, err
	}

	// Read back the value of ProxyEnable
	proxyEnable, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil {
		return "", "", false, err
	}

	host, port, err = net.SplitHostPort(address)
	if err != nil {
		return "", "", false, err
	}

	return host, port, proxyEnable == 1, nil
}

func getSOCKSProxy() (host string, port string, enabled bool, err error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return "", "", false, err
	}
	defer key.Close()

	address, _, err := key.GetStringValue("ProxyServer")
	h := strings.TrimPrefix(address, "socks=")

	host, port, err = net.SplitHostPort(h)
	if err != nil {
		return "", "", false, err
	}
	// Read back the value of ProxyEnable
	proxyEnable, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil {
		return "", "", false, err
	}

	return host, port, proxyEnable == 1, nil
}
