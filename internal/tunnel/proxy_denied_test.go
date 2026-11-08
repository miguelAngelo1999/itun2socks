package tunnel

import (
	"errors"
	"testing"

	"github.com/igoogolx/itun2socks/pkg/clash/transport/socks5"
	"github.com/stretchr/testify/assert"
)

func TestIsProxyDenied(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{nil, false},
		{errors.New("connection timeout"), false},
		{errors.New("upstream proxy denied connection (HTTP 403 Forbidden)"), true},
		{errors.New("upstream proxy authentication required (HTTP 407)"), true},
		{errors.New("upstream proxy gateway error (HTTP 502 Bad Gateway)"), true},
		{errors.New("upstream proxy rejected connection: HTTP 400 Bad Request"), true},
		{socks5.ErrConnectionNotAllowed, true},
		{socks5.ErrConnectionRefused, true},
		{errors.New("proxy auth rejected — awaiting new credentials"), true},
		{errors.New("CONNECT method not allowed by proxy"), true},
	}

	for _, tt := range tests {
		name := "nil"
		if tt.err != nil {
			name = tt.err.Error()
		}
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsProxyDenied(tt.err))
		})
	}
}
