package pac

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// OSProxyEntry represents a proxy endpoint discovered from OS settings, env
// variables, or LAN probing.
type OSProxyEntry struct {
	Host   string
	Port   string
	Type   string // "http" or "socks5"
	Source string // e.g. "os-manual", "env", "lan-probe"
}

// OSProxyConfig holds proxy & network discovery hints collected natively from
// the operating system (without touching Lux's own TUN/loopback overrides).
type OSProxyConfig struct {
	PacURL        string
	PacSource     string // "dhcp-252", "os-pac", "saved-pac", etc.
	ManualProxies []OSProxyEntry
	Gateways      []string
	DNSSuffixes   []string
	PrivateDNS    []string
}

// WPADProbeResult carries a discovered PAC URL alongside its discovery source.
type WPADProbeResult struct {
	URL    string
	Source string // "dhcp-252", "os-pac", "saved-pac", "wpad-probe"
}

// PACProxyEntry is a proxy upstream extracted from a PAC script.
type PACProxyEntry struct {
	Host string
	Port string
	Type string // "http" or "socks5"
}

var (
	blockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineCommentRe  = regexp.MustCompile(`(?m)//[^\n]*`)
	pacDirectiveRe = regexp.MustCompile(`(?i)\b(PROXY|HTTP|HTTPS|SOCKS5|SOCKS)\s+([0-9a-zA-Z._-]+:[0-9]+)`)
)

// StripJSComments removes /* ... */ and // ... comments from PAC JavaScript
// while leaving http:// and https:// URLs intact.
func StripJSComments(js string) string {
	noBlock := blockCommentRe.ReplaceAllString(js, " ")
	var lines []string
	for _, line := range strings.Split(noBlock, "\n") {
		// Remove // comments that are NOT preceded by ':' (so http:// stays intact).
		if idx := findLineComment(line); idx >= 0 {
			line = line[:idx]
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func findLineComment(line string) int {
	inSingle := false
	inDouble := false
	for i := 0; i < len(line)-1; i++ {
		ch := line[i]
		if ch == '\\' && (inSingle || inDouble) {
			i++
			continue
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble && ch == '/' && line[i+1] == '/' {
			if i > 0 && line[i-1] == ':' {
				continue
			}
			return i
		}
	}
	return -1
}

// ExtractProxiesFromPAC discovers proxy upstreams from PAC JavaScript using:
//  1. Live Goja evaluation of FindProxyForURL against representative external
//     URLs (captures dynamic JS string concatenation & subnet-specific winners
//     first).
//  2. Comment-stripped static regex extraction of PROXY / HTTP / HTTPS / SOCKS /
//     SOCKS5 host:port directives (captures backup/alternate upstreams).
func ExtractProxiesFromPAC(js string) []PACProxyEntry {
	seen := make(map[string]bool)
	var out []PACProxyEntry

	add := func(scheme, host, port string) {
		host = strings.TrimSpace(host)
		port = strings.TrimSpace(port)
		if host == "" || port == "" || isLoopbackHost(host) {
			return
		}
		if pNum, err := strconv.Atoi(port); err != nil || pNum <= 0 || pNum > 65535 {
			return
		}
		typ := "http"
		if strings.EqualFold(scheme, "socks5") || strings.EqualFold(scheme, "socks") {
			typ = "socks5"
		}
		key := typ + "|" + strings.ToLower(host) + ":" + port
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, PACProxyEntry{Host: host, Port: port, Type: typ})
	}

	// 1. Live JS evaluation for current subnet/environment.
	if compiled, err := Compile(js); err == nil {
		testURLs := [][2]string{
			{"https://www.google.com/", "www.google.com"},
			{"https://example.com/", "example.com"},
			{"https://github.com/", "github.com"},
			{"http://1.1.1.1/", "1.1.1.1"},
		}
		for _, pair := range testURLs {
			res := compiled.Eval(pair[0], pair[1])
			if res == "" {
				continue
			}
			for _, d := range ParseDirectives(res) {
				if !d.IsDirect() {
					add(d.Scheme, d.Host, d.Port)
				}
			}
		}
	}

	// 2. Static extraction across comment-stripped source.
	cleaned := StripJSComments(js)
	for _, m := range pacDirectiveRe.FindAllStringSubmatch(cleaned, -1) {
		kw := strings.ToUpper(m[1])
		h, p, err := net.SplitHostPort(m[2])
		if err != nil {
			continue
		}
		scheme := "http"
		if kw == "SOCKS" || kw == "SOCKS5" {
			scheme = "socks5"
		}
		add(scheme, h, p)
	}

	return out
}

// BuildWPADCandidates constructs a prioritized, deduplicated list of WPAD / PAC
// candidate URLs following RFC WPAD domain walking plus gateway & LAN DNS checks.
func BuildWPADCandidates(suffixes, gateways, privateDNS []string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}

	// Standard unqualified WPAD first (resolved via direct LAN DNS on Windows).
	add("http://wpad/wpad.dat")
	add("http://wpad/proxy.pac")

	// RFC WPAD DNS suffix walk: sub.corp.local -> wpad.sub.corp.local, wpad.corp.local
	for _, rawSfx := range suffixes {
		sfx := strings.Trim(strings.TrimSpace(rawSfx), ".")
		if sfx == "" {
			continue
		}
		labels := strings.Split(sfx, ".")
		for i := 0; i < len(labels); i++ {
			dom := strings.Join(labels[i:], ".")
			// Skip bare public TLDs like ".com" or ".br" (require at least 2 labels
			// unless it's a single-label internal suffix like "local" / "lan" / "corp").
			if len(labels) > 1 && len(labels)-i < 2 {
				continue
			}
			add("http://wpad." + dom + "/wpad.dat")
			add("http://wpad." + dom + "/proxy.pac")
		}
	}

	// Physical router gateway(s)
	for _, gw := range gateways {
		gw = strings.TrimSpace(gw)
		if gw == "" || isLoopbackHost(gw) {
			continue
		}
		add("http://" + gw + "/wpad.dat")
		add("http://" + gw + "/proxy.pac")
	}

	// Private LAN DNS servers (often run Squid + Apache WPAD on corporate networks)
	for _, dnsIP := range privateDNS {
		dnsIP = strings.TrimSpace(dnsIP)
		if dnsIP == "" || isLoopbackHost(dnsIP) {
			continue
		}
		add("http://" + dnsIP + "/wpad.dat")
		add("http://" + dnsIP + "/proxy.pac")
	}

	return out
}

// ProbeWPADUrlWithSource tries OS-configured PAC / DHCP option 252 first, then
// probes prioritized WPAD & PAC candidate URLs in parallel (bypassing TUN).
func ProbeWPADUrlWithSource() WPADProbeResult {
	cfg := DetectOSProxyConfig()
	if cfg.PacURL != "" {
		return WPADProbeResult{URL: cfg.PacURL, Source: cfg.PacSource}
	}

	candidates := BuildWPADCandidates(cfg.DNSSuffixes, cfg.Gateways, cfg.PrivateDNS)
	if u := probeURLsParallelPrioritized(candidates); u != "" {
		return WPADProbeResult{URL: u, Source: "wpad-probe"}
	}
	return WPADProbeResult{}
}

// ProbeProxyHostPAC checks whether a discovered proxy server itself hosts a PAC
// script at http://<host>/wpad.dat or http://<host>/proxy.pac.
func ProbeProxyHostPAC(host string) string {
	host = strings.TrimSpace(host)
	if host == "" || isLoopbackHost(host) {
		return ""
	}
	candidates := []string{
		"http://" + host + "/wpad.dat",
		"http://" + host + "/proxy.pac",
	}
	return probeURLsParallelPrioritized(candidates)
}

// probeURLsParallelPrioritized probes every candidate concurrently and returns
// the highest-priority (lowest index) URL that serves a valid PAC script.
func probeURLsParallelPrioritized(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2600*time.Millisecond)
	defer cancel()

	type probeRes struct {
		idx int
		url string
	}
	results := make([]string, len(candidates))
	var wg sync.WaitGroup
	var mu sync.Mutex
	foundIdx := -1

	for i, u := range candidates {
		i, u := i, u
		wg.Add(1)
		go func() {
			defer wg.Done()
			if probePACURL(ctx, u) {
				mu.Lock()
				results[i] = u
				if foundIdx == -1 || i < foundIdx {
					foundIdx = i
				}
				// If our top-priority candidate succeeded, cancel slower probes.
				if i == 0 {
					cancel()
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	for _, u := range results {
		if u != "" {
			log.Infoln("[wpad] found via parallel probe: %s", u)
			return u
		}
	}
	return ""
}

// probePACURL fetches [rawURL] bypassing both the system proxy and Lux's TUN
// interface (using direct LAN DNS resolution so single-label "wpad" works on
// Windows), and verifies that the response is HTTP 200 containing a PAC
// FindProxyForURL function.
func probePACURL(ctx context.Context, rawURL string) bool {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return false
	}

	dialCtx := makeBypassDialContext(u.Scheme, u.Port(), 1800*time.Millisecond)
	client := &http.Client{
		Timeout: 2200 * time.Millisecond,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dialCtx,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 1500 * time.Millisecond,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	if err != nil {
		return false
	}
	return LooksLikePACScript(string(b))
}

// LooksLikePACScript checks whether body is a valid PAC JavaScript script
// (rejecting HTML router login pages and empty responses).
func LooksLikePACScript(body string) bool {
	if len(body) < 20 {
		return false
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "findproxyforurl") {
		return false
	}
	trimmed := strings.TrimSpace(lower)
	if strings.HasPrefix(trimmed, "<!doctype html") || strings.HasPrefix(trimmed, "<html") {
		return false
	}
	return true
}

func makeBypassDialContext(scheme, defaultPort string, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = defaultPort
			if port == "" {
				if strings.EqualFold(scheme, "https") {
					port = "443"
				} else {
					port = "80"
				}
			}
		}

		// Fresh LAN DNS resolution avoiding Fake-IPs and Windows Dnscache
		// single-label stalls.
		ipStr := LookupFreshIPv4Strict(ctx, host, false)
		targetHost := host
		if ipStr != "" {
			targetHost = ipStr
		}
		targetIP := net.ParseIP(targetHost)
		if targetIP == nil {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, net.JoinHostPort(host, port))
		}

		var opts []dialer.Option
		defIface := dialer.DefaultInterface.Load()
		if IsExcludedTunIface(defIface) {
			defIface = ""
		}
		if !IsBypassed(targetIP) && !targetIP.IsPrivate() && defIface != "" {
			opts = append(opts, dialer.WithInterface(defIface))
		} else {
			opts = append(opts, dialer.WithInterface(""))
		}
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return dialer.DialContext(dialCtx, network, net.JoinHostPort(targetHost, port), opts...)
	}
}

// EnvProxyEntries reads standard HTTP_PROXY / HTTPS_PROXY / ALL_PROXY env vars,
// ignoring loopback (Lux's own local listener) and malformed placeholders.
func EnvProxyEntries() []OSProxyEntry {
	seen := make(map[string]bool)
	var out []OSProxyEntry
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		entry, ok := ParseProxyURLOrAddr(raw, "env")
		if !ok {
			continue
		}
		k := entry.Type + "|" + strings.ToLower(entry.Host) + ":" + entry.Port
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, entry)
	}
	return out
}

// ParseProxyURLOrAddr parses "http://host:port", "socks5://host:port", or bare
// "host:port", rejecting loopback addresses (Lux's own 127.0.0.1 listener) and
// invalid ports.
func ParseProxyURLOrAddr(raw, source string) (OSProxyEntry, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return OSProxyEntry{}, false
	}
	typ := "http"
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := neturl.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return OSProxyEntry{}, false
	}
	switch strings.ToLower(u.Scheme) {
	case "socks", "socks5", "socks5h", "socks4":
		typ = "socks5"
	case "http", "https":
		typ = "http"
	default:
		return OSProxyEntry{}, false
	}
	host := strings.TrimSpace(u.Hostname())
	port := strings.TrimSpace(u.Port())
	if port == "" {
		if typ == "socks5" {
			port = "1080"
		} else {
			port = "8080"
		}
	}
	pNum, err := strconv.Atoi(port)
	if err != nil || pNum <= 0 || pNum > 65535 {
		return OSProxyEntry{}, false
	}
	if isLoopbackHost(host) {
		return OSProxyEntry{}, false
	}
	return OSProxyEntry{Host: host, Port: port, Type: typ, Source: source}, true
}

// ParseWindowsProxyServer parses WinINET's ProxyServer registry string, which
// may be either "host:port" or "http=h:p;https=h:p;socks=h:p".
func ParseWindowsProxyServer(raw, source string) []OSProxyEntry {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []OSProxyEntry
	add := func(e OSProxyEntry, ok bool) {
		if !ok {
			return
		}
		k := e.Type + "|" + strings.ToLower(e.Host) + ":" + e.Port
		if !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}

	if !strings.Contains(raw, "=") {
		e, ok := ParseProxyURLOrAddr(raw, source)
		add(e, ok)
		return out
	}

	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		scheme := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch scheme {
		case "http", "https":
			e, ok := ParseProxyURLOrAddr("http://"+val, source)
			add(e, ok)
		case "socks", "socks5":
			e, ok := ParseProxyURLOrAddr("socks5://"+val, source)
			add(e, ok)
		}
	}
	return out
}

// ProbeLANProxies performs a fast, strict parallel HTTP CONNECT probe against
// physical gateway and private LAN DNS IPs on common corporate proxy ports
// (3128, 8080, 8082, 8888, 8000). It ONLY accepts genuine HTTP proxy responses
// (407 Proxy Auth Required, 200 Connection established, or Proxy-Authenticate /
// X-Squid-Error headers), avoiding false positives from router admin UIs.
func ProbeLANProxies(hosts []string) []OSProxyEntry {
	var uniqueHosts []string
	seenHost := make(map[string]bool)
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" || isLoopbackHost(h) || seenHost[h] {
			continue
		}
		ip := net.ParseIP(h)
		if ip == nil || !ip.IsPrivate() || isExcludedIP(ip) {
			continue
		}
		seenHost[h] = true
		uniqueHosts = append(uniqueHosts, h)
	}
	if len(uniqueHosts) == 0 {
		return nil
	}

	ports := []int{3128, 8080, 8082, 8888, 8000}
	type target struct {
		host  string
		port  int
		order int
	}
	var targets []target
	for hi, h := range uniqueHosts {
		for pi, p := range ports {
			targets = append(targets, target{host: h, port: p, order: hi*len(ports) + pi})
		}
	}

	type found struct {
		entry OSProxyEntry
		order int
	}
	var mu sync.Mutex
	var hits []found
	var wg sync.WaitGroup

	for _, t := range targets {
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			if probeHTTPProxyPort(t.host, t.port, 1100*time.Millisecond) {
				mu.Lock()
				hits = append(hits, found{
					entry: OSProxyEntry{
						Host:   t.host,
						Port:   strconv.Itoa(t.port),
						Type:   "http",
						Source: "lan-probe",
					},
					order: t.order,
				})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	sort.Slice(hits, func(i, j int) bool { return hits[i].order < hits[j].order })
	out := make([]OSProxyEntry, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.entry)
	}
	return out
}

func probeHTTPProxyPort(host string, port int, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := dialer.DialContext(ctx, "tcp", addr, dialer.WithInterface(""))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	_, err = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: LuxProxyProbe/1.0\r\n\r\n")
	if err != nil {
		return false
	}

	br := bufio.NewReader(io.LimitReader(conn, 4096))
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return false
	}
	upperStatus := strings.ToUpper(strings.TrimSpace(statusLine))
	if !strings.HasPrefix(upperStatus, "HTTP/1.") {
		return false
	}

	// Read headers to distinguish genuine HTTP proxies from router web panels.
	var headers []string
	for i := 0; i < 24; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			break
		}
		headers = append(headers, strings.ToLower(trimmed))
	}

	// 407 Proxy Authentication Required is an unmistakable proxy response.
	if strings.Contains(upperStatus, " 407") {
		return true
	}
	// Explicit proxy headers (Squid, Tinyproxy, Privoxy, corporate proxies).
	for _, h := range headers {
		if strings.HasPrefix(h, "proxy-authenticate:") ||
			strings.HasPrefix(h, "proxy-agent:") ||
			strings.HasPrefix(h, "x-squid-error:") {
			return true
		}
		if strings.HasPrefix(h, "server:") &&
			(strings.Contains(h, "squid") ||
				strings.Contains(h, "tinyproxy") ||
				strings.Contains(h, "privoxy") ||
				strings.Contains(h, "polipo") ||
				strings.Contains(h, "ccproxy")) {
			return true
		}
	}
	// 200 Connection Established (open HTTP CONNECT proxy — NOT an HTML page).
	if strings.Contains(upperStatus, " 200") {
		hasContentTypeHTML := false
		for _, h := range headers {
			if strings.HasPrefix(h, "content-type:") && strings.Contains(h, "text/html") {
				hasContentTypeHTML = true
			}
		}
		if !hasContentTypeHTML &&
			(strings.Contains(upperStatus, "ESTABLISHED") ||
				strings.Contains(upperStatus, "CONNECTED") ||
				strings.Contains(upperStatus, "OK")) {
			return true
		}
	}
	return false
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "0.0.0.0" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

func appendUniqueStr(dst []string, val string) []string {
	val = strings.TrimSpace(val)
	if val == "" {
		return dst
	}
	for _, existing := range dst {
		if strings.EqualFold(existing, val) {
			return dst
		}
	}
	return append(dst, val)
}

func appendUniqueProxy(dst []OSProxyEntry, e OSProxyEntry) []OSProxyEntry {
	key := e.Type + "|" + strings.ToLower(e.Host) + ":" + e.Port
	for _, cur := range dst {
		if cur.Type+"|"+strings.ToLower(cur.Host)+":"+cur.Port == key {
			return dst
		}
	}
	return append(dst, e)
}
