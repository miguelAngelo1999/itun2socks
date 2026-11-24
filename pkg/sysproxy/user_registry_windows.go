//go:build windows

package sysproxy

import (
	"regexp"
	"sync"

	"golang.org/x/sys/windows/registry"
)

var (
	userSIDMu     sync.RWMutex
	targetUserSID string
	validSIDRe    = regexp.MustCompile(`^S-1-5-[0-9-]+$`)
)

// SetTargetUserSID configures the Windows user SID whose registry hive
// (HKEY_USERS\<SID>) should be modified for per-user WinINET proxy settings
// and environment variables. This allows an elevated core running under
// LocalSystem (LuxCoreService) or an over-the-shoulder admin account to update
// the actual logged-in desktop user's proxy settings instead of .DEFAULT.
func SetTargetUserSID(sid string) {
	userSIDMu.Lock()
	defer userSIDMu.Unlock()
	if validSIDRe.MatchString(sid) {
		targetUserSID = sid
	} else {
		targetUserSID = ""
	}
}

// GetTargetUserSID returns the configured target user SID, or empty string if
// targeting the current process token's HKCU hive.
func GetTargetUserSID() string {
	userSIDMu.RLock()
	defer userSIDMu.RUnlock()
	return targetUserSID
}

// openUserKey opens [subpath] under HKEY_USERS\<targetUserSID> when a target
// user SID is configured, falling back to HKEY_CURRENT_USER otherwise.
func openUserKey(subpath string, access uint32) (registry.Key, error) {
	sid := GetTargetUserSID()
	if sid != "" {
		k, err := registry.OpenKey(registry.USERS, sid+`\`+subpath, access)
		if err == nil {
			return k, nil
		}
	}
	return registry.OpenKey(registry.CURRENT_USER, subpath, access)
}
