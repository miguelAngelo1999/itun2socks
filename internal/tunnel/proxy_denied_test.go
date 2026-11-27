package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/clash/transport/socks5"
	"github.com/stretchr/testify/assert"
)

func TestIsProxyDenied(t *testing.T) {
	tests := []struct {
		err         error
		expected    bool
		expectedTag string
	}{
		{nil, false, ""},
		{errors.New("connection timeout"), false, ""},
		{errors.New("upstream proxy test-proxy (10.8.0.1:8082) denied connection (HTTP 403 Forbidden) [ERR_ACCESS_DENIED 0]"), true, "HTTP 403"},
		{errors.New("upstream proxy authentication required (HTTP 407)"), true, "HTTP 407"},
		{errors.New("upstream proxy denied connection (HTTP 405 Method Not Allowed)"), true, "HTTP 405"},
		{errors.New("upstream proxy gateway error (HTTP 502 Bad Gateway)"), true, "HTTP 502"},
		{errors.New("upstream proxy rejected connection: HTTP 400 Bad Request"), true, "PROXY DENY"},
		{socks5.ErrConnectionNotAllowed, true, "SOCKS5 DENY"},
		{socks5.ErrConnectionRefused, true, "SOCKS5 ERR"},
		{socks5.ErrAuth, true, "SOCKS5 AUTH"},
		{errors.New("SOCKS5 proxy corp (10.8.0.1:1080): upstream proxy authentication required (SOCKS need auth)"), true, "SOCKS5 AUTH"},
		{errors.New("proxy auth rejected — awaiting new credentials"), true, "AUTH LATCHED"},
		{errors.New("CONNECT method not allowed by proxy"), true, "PROXY DENY"},
	}

	for _, tt := range tests {
		name := "nil"
		if tt.err != nil {
			name = tt.err.Error()
		}
		t.Run(name, func(t *testing.T) {
			tag, denied := ClassifyProxyError(tt.err)
			assert.Equal(t, tt.expected, denied)
			assert.Equal(t, tt.expected, IsProxyDenied(tt.err))
			assert.Equal(t, tt.expectedTag, tag)
		})
	}
}

func TestIsEarlyUpstreamReset(t *testing.T) {
	// Proxied connection where client sent ClientHello (517B) and upstream reset with 0B reply → true
	assert.True(t, isEarlyUpstreamReset(constants.PolicyProxy, 517, 0, 200*time.Millisecond, errors.New("read tcp 10.0.0.2->10.8.0.1:8082: connection reset by peer")))
	// Clean EOF with 7-byte TLS fatal alert → true
	assert.True(t, isEarlyUpstreamReset(constants.PolicyProxy, 300, 7, 150*time.Millisecond, nil))
	// Normal TLS handshake that downloaded bytes → false
	assert.False(t, isEarlyUpstreamReset(constants.PolicyProxy, 517, 2400, 300*time.Millisecond, nil))
	// Direct connection → false
	assert.False(t, isEarlyUpstreamReset(constants.PolicyDirect, 517, 0, 200*time.Millisecond, nil))
	// Local browser hung up (127.0.0.1 broken pipe) → false
	assert.False(t, isEarlyUpstreamReset(constants.PolicyProxy, 517, 0, 200*time.Millisecond, errors.New("download: write tcp 127.0.0.1:1090->127.0.0.1:55271: broken pipe")))
	// Context canceled → false
	assert.False(t, isEarlyUpstreamReset(constants.PolicyProxy, 517, 0, 200*time.Millisecond, context.Canceled))
	// Long-lived connection (>5s) → false
	assert.False(t, isEarlyUpstreamReset(constants.PolicyProxy, 517, 0, 10*time.Second, nil))
}
