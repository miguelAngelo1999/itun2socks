package outbound

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
)

type Http struct {
	*Base
	user      string
	pass      string
	tlsConfig *tls.Config
	Headers   http.Header
	via       string // upstream proxy address for chaining
	viaUser   string
	viaPass   string
}

type HttpOption struct {
	BasicOption
	Name           string            `proxy:"name"`
	Server         string            `proxy:"server"`
	Port           int               `proxy:"port"`
	UserName       string            `proxy:"username,omitempty"`
	Password       string            `proxy:"password,omitempty"`
	TLS            bool              `proxy:"tls,omitempty"`
	SNI            string            `proxy:"sni,omitempty"`
	SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"`
	Headers        map[string]string `proxy:"headers,omitempty"`
	// Via is the address of an upstream proxy to reach this proxy through.
	// Format: "host:port". When set, DialContext first CONNECTs to Via,
	// then CONNECTs through it to the target. This is proxy chaining.
	Via         string `proxy:"via,omitempty"`
	ViaUser     string `proxy:"via-username,omitempty"`
	ViaPassword string `proxy:"via-password,omitempty"`
}

// StreamConn implements C.ProxyAdapter
func (h *Http) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if h.tlsConfig != nil {
		cc := tls.Client(c, h.tlsConfig)
		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()
		err := cc.HandshakeContext(ctx)
		c = cc
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
		}
	}

	if err := h.shakeHand(metadata, c); err != nil {
		return nil, err
	}
	return c, nil
}

// DialContext implements C.ProxyAdapter
func (h *Http) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	var c net.Conn
	if h.via != "" {
		// Proxy chaining: connect to upstream proxy first, then CONNECT to this proxy.
		c, err = dialer.DialContext(ctx, "tcp", h.via, h.Base.DialOptions(opts...)...)
		if err != nil {
			return nil, fmt.Errorf("%s via %s connect error: %w", h.addr, h.via, err)
		}
		tcpKeepAlive(c)
		if err = h.connectVia(c); err != nil {
			c.Close()
			return nil, fmt.Errorf("%s via %s tunnel error: %w", h.addr, h.via, err)
		}
	} else {
		c, err = dialer.DialContext(ctx, "tcp", h.addr, h.Base.DialOptions(opts...)...)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
		}
		tcpKeepAlive(c)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = h.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, h), nil
}

// proxyLabel returns a human-readable identifier for this upstream proxy,
// combining name and host:port when both are useful.
func (h *Http) proxyLabel() string {
	name := strings.TrimSpace(h.Name())
	if name == "" || name == h.addr {
		return h.addr
	}
	return fmt.Sprintf("%s (%s)", name, h.addr)
}

// extractProxyDenyReason pulls diagnostic hints that corporate proxies
// (Squid, OpenSWG, FortiGate, BlueCoat, etc.) attach to 403/405/407/5xx
// CONNECT responses — headers first, then a bounded <title> or plain text line.
func extractProxyDenyReason(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	var hints []string
	for _, key := range []string{
		"X-Squid-Error",
		"X-Block-Reason",
		"X-OpenSWG-Rule",
		"X-Swg-Rule",
		"X-Denied-Reason",
		"X-Category",
	} {
		if v := strings.TrimSpace(resp.Header.Get(key)); v != "" {
			if key == "X-Squid-Error" {
				hints = append(hints, v)
			} else {
				hints = append(hints, key+"="+v)
			}
		}
	}
	if len(hints) > 0 {
		return clampLogHint(strings.Join(hints, ", "), 140)
	}

	if resp.Body != nil {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		text := strings.TrimSpace(string(raw))
		if text != "" {
			lower := strings.ToLower(text)
			if start := strings.Index(lower, "<title>"); start >= 0 {
				rest := text[start+len("<title>"):]
				if end := strings.Index(strings.ToLower(rest), "</title>"); end >= 0 {
					title := collapseWhitespace(rest[:end])
					if title != "" && !strings.EqualFold(title, resp.Status) {
						return clampLogHint(title, 120)
					}
				}
			} else if !strings.HasPrefix(text, "<") {
				line := text
				if nl := strings.IndexAny(line, "\r\n"); nl >= 0 {
					line = line[:nl]
				}
				line = collapseWhitespace(line)
				if line != "" && !strings.EqualFold(line, resp.Status) {
					return clampLogHint(line, 120)
				}
			}
		}
	}
	return ""
}

func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func clampLogHint(s string, maxLen int) string {
	s = collapseWhitespace(s)
	if len(s) > maxLen {
		return s[:maxLen-1] + "…"
	}
	return s
}

func cleanHTTPStatusText(resp *http.Response) string {
	codePrefix := strconv.Itoa(resp.StatusCode)
	text := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(resp.Status), codePrefix))
	if text == "" {
		text = http.StatusText(resp.StatusCode)
	}
	return text
}

func formatHttpProxyError(proxyLabel string, resp *http.Response) error {
	reason := extractProxyDenyReason(resp)
	suffix := ""
	if reason != "" {
		suffix = " [" + reason + "]"
	}
	statusText := cleanHTTPStatusText(resp)

	switch {
	case resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("upstream proxy %s denied connection (HTTP 403 Forbidden)%s", proxyLabel, suffix)
	case resp.StatusCode == http.StatusProxyAuthRequired:
		return fmt.Errorf("upstream proxy %s authentication required (HTTP 407)%s", proxyLabel, suffix)
	case resp.StatusCode == http.StatusMethodNotAllowed:
		return fmt.Errorf("upstream proxy %s denied connection (HTTP 405 Method Not Allowed)%s", proxyLabel, suffix)
	case resp.StatusCode >= http.StatusInternalServerError:
		return fmt.Errorf("upstream proxy %s gateway error (HTTP %d %s)%s", proxyLabel, resp.StatusCode, statusText, suffix)
	default:
		return fmt.Errorf("upstream proxy %s rejected connection: HTTP %d %s%s", proxyLabel, resp.StatusCode, statusText, suffix)
	}
}

// connectVia tunnels through the upstream proxy to reach this proxy's address.
func (h *Http) connectVia(c net.Conn) error {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: h.addr},
		Host:   h.addr,
		Header: make(http.Header),
	}
	if h.viaUser != "" {
		auth := h.viaUser + ":" + h.viaPass
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}
	if err := req.Write(c); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return formatHttpProxyError(h.via, resp)
	}
	resp.Body.Close()
	return nil
}

func (h *Http) shakeHand(metadata *C.Metadata, rw io.ReadWriter) error {
	addr := metadata.RemoteAddress()
	req := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Host: addr,
		},
		Host:   addr,
		Header: h.Headers.Clone(),
	}

	req.Header.Add("Proxy-Connection", "Keep-Alive")

	if h.user != "" {
		auth := h.user + ":" + h.pass
		req.Header.Add("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	if err := req.Write(rw); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(rw), req)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	return formatHttpProxyError(h.proxyLabel(), resp)
}

func NewHttp(option HttpOption) *Http {
	option.Server = strings.TrimSpace(option.Server)
	option.UserName = strings.TrimSpace(option.UserName)
	option.Name = strings.TrimSpace(option.Name)

	var tlsConfig *tls.Config
	if option.TLS {
		sni := option.Server
		if option.SNI != "" {
			sni = option.SNI
		}
		tlsConfig = &tls.Config{
			InsecureSkipVerify: option.SkipCertVerify,
			ServerName:         sni,
		}
	}

	header := http.Header{}
	for name, value := range option.Headers {
		header.Add(name, value)
	}

	return &Http{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Http,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		user:      option.UserName,
		pass:      option.Password,
		tlsConfig: tlsConfig,
		Headers:   header,
		via:       option.Via,
		viaUser:   option.ViaUser,
		viaPass:   option.ViaPassword,
	}
}
