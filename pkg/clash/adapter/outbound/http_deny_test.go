package outbound

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHttpProxyDenialErrorDetails(t *testing.T) {
	tests := []struct {
		name     string
		response string
		contains []string
	}{
		{
			name: "squid 403 with X-Squid-Error",
			response: "HTTP/1.1 403 Forbidden\r\n" +
				"Server: squid/6.10\r\n" +
				"X-Squid-Error: ERR_ACCESS_DENIED 0\r\n" +
				"Content-Length: 0\r\n\r\n",
			contains: []string{"OfficeProxy", "HTTP 403 Forbidden", "ERR_ACCESS_DENIED 0"},
		},
		{
			name: "openswg 403 with block reason header",
			response: "HTTP/1.1 403 Forbidden\r\n" +
				"X-OpenSWG-Rule: social-block\r\n" +
				"X-Category: Social Media\r\n" +
				"Content-Length: 0\r\n\r\n",
			contains: []string{"OfficeProxy", "HTTP 403 Forbidden", "X-OpenSWG-Rule=social-block", "X-Category=Social Media"},
		},
		{
			name: "403 with HTML title fallback",
			response: "HTTP/1.1 403 Forbidden\r\n" +
				"Content-Type: text/html\r\n" +
				"Content-Length: 62\r\n\r\n" +
				"<html><head><title>Blocked by Policy</title></head><body>x</body></html>",
			contains: []string{"OfficeProxy", "HTTP 403 Forbidden", "Blocked by Policy"},
		},
		{
			name: "502 bad gateway has clean non-duplicated status",
			response: "HTTP/1.1 502 Bad Gateway\r\n" +
				"Content-Length: 0\r\n\r\n",
			contains: []string{"OfficeProxy", "HTTP 502 Bad Gateway"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()

			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = http.ReadRequest(bufio.NewReader(c))
				_, _ = io.WriteString(c, tt.response)
			}()

			host, portStr, err := net.SplitHostPort(ln.Addr().String())
			require.NoError(t, err)
			var port int
			for _, ch := range portStr {
				port = port*10 + int(ch-'0')
			}

			h := NewHttp(HttpOption{
				Name:   "OfficeProxy",
				Server: host,
				Port:   port,
			})
			_, err = h.DialContext(context.Background(), &C.Metadata{
				Host:    "blocked.example.com",
				DstPort: 443,
			})
			require.Error(t, err)
			for _, want := range tt.contains {
				assert.Contains(t, err.Error(), want)
			}
			assert.NotContains(t, err.Error(), "502 502")
			assert.False(t, strings.Contains(err.Error(), "\n"))
		})
	}
}
