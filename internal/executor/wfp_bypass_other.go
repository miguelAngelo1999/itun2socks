//go:build !windows

package executor

// ApplyProcessBypasses is a no-op on non-Windows platforms.
// macOS does not have a kernel-level per-process packet filter equivalent to WFP.
// Process-based DIRECT rules are still handled by the rule engine after TUN capture.
func ApplyProcessBypasses() {}

// CloseWfpBypass is a no-op on non-Windows platforms.
func CloseWfpBypass() {}
