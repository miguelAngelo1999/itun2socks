package executor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaitForDefaultInterface_Immediate(t *testing.T) {
	calls := 0
	name, err := waitForDefaultInterface(func() string {
		calls++
		return "en0"
	}, defaultInterfaceWaitAttempts, time.Millisecond)

	require.NoError(t, err)
	assert.Equal(t, "en0", name)
	assert.Equal(t, 1, calls)
}

func TestWaitForDefaultInterface_BecomesAvailable(t *testing.T) {
	calls := 0
	name, err := waitForDefaultInterface(func() string {
		calls++
		if calls >= 3 {
			return "en5"
		}
		return ""
	}, defaultInterfaceWaitAttempts, time.Millisecond)

	require.NoError(t, err)
	assert.Equal(t, "en5", name)
	assert.Equal(t, 3, calls)
}

func TestWaitForDefaultInterface_TimesOutWhenOffline(t *testing.T) {
	calls := 0
	name, err := waitForDefaultInterface(func() string {
		calls++
		return ""
	}, defaultInterfaceWaitAttempts, time.Millisecond)

	require.Error(t, err)
	assert.Empty(t, name)
	assert.EqualError(t, err, "no active default network interface")
	assert.Equal(t, defaultInterfaceWaitAttempts, calls)
}

func TestWaitForDefaultInterface_ConstantsBounded(t *testing.T) {
	assert.Equal(t, 8, defaultInterfaceWaitAttempts)
	assert.Equal(t, time.Second, defaultInterfaceWaitInterval)
}
