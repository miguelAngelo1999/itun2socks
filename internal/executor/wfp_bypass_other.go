//go:build !windows

package executor

// ApplyProcessBypasses is a no-op on non-Windows platforms.
// macOS does not have a kernel-level per-process packet filter equivalent to WFP.
// Process-based DIRECT rules are still handled by the rule engine after TUN capture.
func ApplyProcessBypasses() {}

// CloseWfpBypass is a no-op on non-Windows platforms.
func CloseWfpBypass() {}

// ApplyUdpBlock is a no-op on non-Windows platforms.
func ApplyUdpBlock() error { return nil }

// CloseUdpBlock is a no-op on non-Windows platforms.
func CloseUdpBlock() {}

// IsUdpBlockActive reports whether the dynamic WFP UDP block is currently applied (always false on non-Windows).
func IsUdpBlockActive() bool { return false }
