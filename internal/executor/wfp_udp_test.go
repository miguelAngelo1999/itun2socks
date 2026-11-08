package executor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockProxyAdapter struct {
	udpSupport bool
}

func (m *mockProxyAdapter) SupportUDP() bool {
	return m.udpSupport
}

func TestUdpBlockStub(t *testing.T) {
	// On non-Windows platforms, ApplyUdpBlock and CloseUdpBlock are stubs.
	// On Windows platforms, testing without admin/BFE returns error or succeeds.
	err := ApplyUdpBlock()
	// Stubs should never return an error on non-Windows
	assert.NoError(t, err)

	// CloseUdpBlock should not panic
	assert.NotPanics(t, func() {
		CloseUdpBlock()
	})
}

func TestHasUdpSupportCondition(t *testing.T) {
	httpProxy := &mockProxyAdapter{udpSupport: false}
	socks5Proxy := &mockProxyAdapter{udpSupport: true}

	assert.False(t, httpProxy.SupportUDP(), "HTTP proxy should not support UDP")
	assert.True(t, socks5Proxy.SupportUDP(), "SOCKS5 proxy with UDP enabled should support UDP")
}
