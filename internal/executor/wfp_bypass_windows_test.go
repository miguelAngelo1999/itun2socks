//go:build windows

package executor

import (
	"os"
	"testing"
	"unsafe"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time ABI verification for 64-bit Windows (amd64 & arm64):
// fails cross-compilation if FWPM_FILTER0 layout drifts by even 1 byte.
var _ = func() {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		const (
			_ = uint(200 - unsafe.Sizeof(fwpmFilter0{}))
			_ = uint(unsafe.Sizeof(fwpmFilter0{}) - 200)
			_ = uint(128 - unsafe.Offsetof(fwpmFilter0{}.action))
			_ = uint(unsafe.Offsetof(fwpmFilter0{}.action) - 128)
			_ = uint(152 - unsafe.Offsetof(fwpmFilter0{}.providerContextKey))
			_ = uint(unsafe.Offsetof(fwpmFilter0{}.providerContextKey) - 152)
			_ = uint(168 - unsafe.Offsetof(fwpmFilter0{}.reserved))
			_ = uint(unsafe.Offsetof(fwpmFilter0{}.reserved) - 168)
			_ = uint(176 - unsafe.Offsetof(fwpmFilter0{}.filterId))
			_ = uint(unsafe.Offsetof(fwpmFilter0{}.filterId) - 176)
			_ = uint(184 - unsafe.Offsetof(fwpmFilter0{}.effectiveWeight))
			_ = uint(unsafe.Offsetof(fwpmFilter0{}.effectiveWeight) - 184)
		)
	}
}

func TestFwpmFilter0StructLayout(t *testing.T) {
	// Verify 64-bit Windows ABI layout matches Win32 SDK FWPM_FILTER0 in fwpmtypes.h.
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64-bit ABI layout assertions only")
	}
	var f fwpmFilter0
	assert.Equal(t, uintptr(200), unsafe.Sizeof(f), "FWPM_FILTER0 must be 200 bytes on 64-bit Windows")
	assert.Equal(t, uintptr(128), unsafe.Offsetof(f.action))
	assert.Equal(t, uintptr(152), unsafe.Offsetof(f.providerContextKey))
	assert.Equal(t, uintptr(168), unsafe.Offsetof(f.reserved))
	assert.Equal(t, uintptr(176), unsafe.Offsetof(f.filterId))
	assert.Equal(t, uintptr(184), unsafe.Offsetof(f.effectiveWeight))
	assert.Equal(t, uint32(0x00000008), uint32(fwpmFilterFlagClearActionRight))
}

func TestAddProcessBypassWithProtocol_RejectsUnknownProtocol(t *testing.T) {
	err := AddProcessBypassWithProtocol(`C:\Windows\System32\cmd.exe`, constants.RuleProtocol("icmp"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported WFP bypass protocol")
}

func TestWfpBypassLiveBFE(t *testing.T) {
	if os.Getenv("LUX_TEST_LIVE_WFP") != "1" {
		t.Skip("set LUX_TEST_LIVE_WFP=1 on an elevated Windows host to run live BFE test")
	}
	t.Cleanup(CloseWfpBypass)

	require.NoError(t, InitWfpBypass())
	exe := `C:\Windows\System32\cmd.exe`
	require.NoError(t, AddProcessBypassWithProtocol(exe, constants.RuleProtocolAny))
	require.NoError(t, AddProcessBypassWithProtocol(exe, constants.RuleProtocolTCP))
	require.NoError(t, AddProcessBypassWithProtocol(exe, constants.RuleProtocolUDP))
	CloseWfpBypass()
}
