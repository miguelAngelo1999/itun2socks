package http

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/igoogolx/itun2socks/pkg/clash/adapter/inbound"
	"github.com/igoogolx/itun2socks/pkg/clash/common/cache"
	N "github.com/igoogolx/itun2socks/pkg/clash/common/net"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	authStore "github.com/igoogolx/itun2socks/pkg/clash/listener/auth"
	"github.com/igoogolx/itun2socks/pkg/clash/log"
)

func HandleConn(c net.Conn, in chan<- C.ConnContext, cache *cache.LruCache) {
	client := newClient(c.RemoteAddr(), c.LocalAddr(), in)
	defer client.CloseIdleConnections()

	conn := N.NewBufferedConn(c)

	keepAlive := true
	trusted := cache == nil // disable authenticate if cache is nil

	for keepAlive {
		request, err := ReadRequest(conn.Reader())
		if err != nil {
			break
		}

		request.RemoteAddr = conn.RemoteAddr().String()

		keepAlive = strings.TrimSpace(strings.ToLower(request.Header.Get("Proxy-Connection"))) == "keep-alive"

		var resp *http.Response

		if !trusted {
			resp = authenticate(request, cache)

			trusted = resp == nil
		}

		if trusted {
			if request.Method == http.MethodConnect {
				// Manual writing to support CONNECT for http 1.0 (workaround for uplay client)
				if _, err = fmt.Fprintf(conn, "HTTP/%d.%d %03d %s\r\n\r\n", request.ProtoMajor, request.ProtoMinor, http.StatusOK, "Connection established"); err != nil {
					break // close connection
				}

				in <- inbound.NewHTTPS(request, conn)

				return // hijack connection
			}

			host := request.Header.Get("Host")
			if host != "" {
				request.Host = host
			}

			request.RequestURI = ""

			if isUpgradeRequest(request) {
				handleUpgrade(conn, request, in)

				return // hijack connection
			}

			removeHopByHopHeaders(request.Header)
			removeExtraHTTPHostPort(request)

			if request.URL.Scheme == "" || request.URL.Host == "" {
				resp = responseWith(request, http.StatusBadRequest)
			} else {
				resp, err = client.Do(request)
				if err != nil {
					log.Warnln("[TCP], [DIAL_FAIL] HTTP %s %s — %v", request.Method, request.URL.String(), err)
					resp = responseWith(request, http.StatusBadGateway)
				} else if isUpstreamHTTPProxyDenial(resp) {
					hint := plainHTTPProxyHint(resp)
					if hint != "" {
						hint = " [" + hint + "]"
					}
					log.Warnln("[TCP], [DENY] [PROXY_DENIED] [HTTP %d] %s %s — upstream proxy returned %s%s", resp.StatusCode, request.Method, request.URL.String(), resp.Status, hint)
				}
			}

			removeHopByHopHeaders(resp.Header)
		}

		if keepAlive {
			resp.Header.Set("Proxy-Connection", "keep-alive")
			resp.Header.Set("Connection", "keep-alive")
			resp.Header.Set("Keep-Alive", "timeout=4")
		}

		resp.Close = !keepAlive

		err = resp.Write(conn)
		if err != nil {
			break // close connection
		}
	}

	conn.Close()
}

func authenticate(request *http.Request, cache *cache.LruCache) *http.Response {
	authenticator := authStore.Authenticator()
	if authenticator != nil {
		credential := parseBasicProxyAuthorization(request)
		if credential == "" {
			resp := responseWith(request, http.StatusProxyAuthRequired)
			resp.Header.Set("Proxy-Authenticate", "Basic")
			return resp
		}

		authed, exist := cache.Get(credential)
		if !exist {
			user, pass, err := decodeBasicProxyAuthorization(credential)
			authed = err == nil && authenticator.Verify(user, pass)
			cache.Set(credential, authed)
		}
		if !authed.(bool) {
			log.Infoln("Auth failed from %s", request.RemoteAddr)

			return responseWith(request, http.StatusForbidden)
		}
	}

	return nil
}

func responseWith(request *http.Request, statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Proto:      request.Proto,
		ProtoMajor: request.ProtoMajor,
		ProtoMinor: request.ProtoMinor,
		Header:     http.Header{},
	}
}

func isUpstreamHTTPProxyDenial(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusProxyAuthRequired {
		return true
	}
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusMethodNotAllowed {
		return false
	}
	for _, key := range []string{"X-Squid-Error", "X-Block-Reason", "X-OpenSWG-Rule", "X-Swg-Rule", "X-Denied-Reason", "Proxy-Authenticate"} {
		if strings.TrimSpace(resp.Header.Get(key)) != "" {
			return true
		}
	}
	server := strings.ToLower(resp.Header.Get("Server") + " " + resp.Header.Get("Via"))
	for _, kw := range []string{"squid", "proxy", "openswg", "forti", "bluecoat", "zscaler", "netskope", "mwg"} {
		if strings.Contains(server, kw) {
			return true
		}
	}
	return false
}

func plainHTTPProxyHint(resp *http.Response) string {
	var parts []string
	for _, key := range []string{"X-Squid-Error", "X-Block-Reason", "X-OpenSWG-Rule", "X-Category", "Server"} {
		if v := strings.TrimSpace(resp.Header.Get(key)); v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ", ")
}
