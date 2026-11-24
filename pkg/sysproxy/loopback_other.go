//go:build !windows

package sysproxy

// No-ops on non-Windows platforms.
func EnsureUWPLoopbackExemptions() {}
func applyUWPLoopbackExemptions()  {}
func clearUWPLoopbackExemptions()  {}
