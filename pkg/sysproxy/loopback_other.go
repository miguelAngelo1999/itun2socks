//go:build !windows

package sysproxy

// No-ops on non-Windows platforms.
func applyUWPLoopbackExemptions() {}
func clearUWPLoopbackExemptions()  {}
