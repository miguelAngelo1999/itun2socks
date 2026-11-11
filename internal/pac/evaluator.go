// Package pac provides PAC (Proxy Auto-Config) evaluation.
//
// Eval evaluates FindProxyForURL(url, host) using an embedded ECMAScript runtime
// (github.com/dop251/goja) with standard PAC helper functions.
package pac

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// ── DNS cache & lookups ──────────────────────────────────────────────────────

type LocalLookupFunc func(ctx context.Context, host string) ([]string, error)

var (
	dnsCache      *lru.Cache[string, string]
	dnsCacheOnce  sync.Once
	localLookup   LocalLookupFunc
	localLookupMu sync.RWMutex

	excludedTunIface string
	excludedTunMu    sync.RWMutex

	isBypassedFn func(net.IP) bool
	isBypassedMu sync.RWMutex
)

func getDNSCache() *lru.Cache[string, string] {
	dnsCacheOnce.Do(func() {
		c, _ := lru.New[string, string](512)
		dnsCache = c
	})
	return dnsCache
}

// SetLocalLookup sets the local DNS resolver callback (e.g. from local DHCP client).
func SetLocalLookup(fn LocalLookupFunc) {
	localLookupMu.Lock()
	defer localLookupMu.Unlock()
	localLookup = fn
}

// SetExcludedTunIface registers the Lux TUN device name so detectMyIP will skip it.
func SetExcludedTunIface(name string) {
	excludedTunMu.Lock()
	defer excludedTunMu.Unlock()
	excludedTunIface = name
}

// SetIsBypassed registers the bypass predicate checking if an IP is excluded from TUN routing.
func SetIsBypassed(fn func(net.IP) bool) {
	isBypassedMu.Lock()
	defer isBypassedMu.Unlock()
	isBypassedFn = fn
}

// IsBypassed reports whether the given IP is covered by the active bypass prefixes.
func IsBypassed(ip net.IP) bool {
	isBypassedMu.RLock()
	defer isBypassedMu.RUnlock()
	if isBypassedFn != nil {
		return isBypassedFn(ip)
	}
	return false
}

func isFakeIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// 198.18.0.0/15 RFC 2544
	return ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}

func isExcludedIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return true
	}
	// 198.18.0.0/15
	if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
		return true
	}
	// 10.255.0.0/16
	if ip4[0] == 10 && ip4[1] == 255 {
		return true
	}
	return false
}

// GoLookup resolves host to its first IPv4 address, ignoring Fake-IPs (198.18.0.0/15).
func GoLookup(host string) string {
	return goLookup(host)
}

func goLookup(host string) string {
	cache := getDNSCache()
	if v, ok := cache.Get(host); ok {
		return v
	}

	if ip := net.ParseIP(host); ip != nil {
		if !isFakeIP(ip) && ip.To4() != nil {
			return host
		}
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// 1. Try local lookup if registered
	localLookupMu.RLock()
	fn := localLookup
	localLookupMu.RUnlock()
	if fn != nil {
		addrs, err := fn(ctx, host)
		if err == nil {
			for _, a := range addrs {
				if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && !isFakeIP(ip) {
					cache.Add(host, a)
					return a
				}
			}
		}
	}

	// 2. Fallback to system resolver
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err == nil {
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && !isFakeIP(ip) {
				cache.Add(host, a)
				return a
			}
		}
	}

	return ""
}

// ── myIpAddress ──────────────────────────────────────────────────────────────

var (
	myIPCache string
	myIPMu    sync.RWMutex
)

// RefreshMyIP re-derives the local IP (call on network change).
func RefreshMyIP() {
	myIPMu.Lock()
	defer myIPMu.Unlock()
	myIPCache = detectMyIP()
}

func detectMyIP() string {
	excludedTunMu.RLock()
	excludedIface := excludedTunIface
	excludedTunMu.RUnlock()

	// 1. Prefer dialer.DefaultInterface if set and valid
	if defIface := dialer.DefaultInterface.Load(); defIface != "" && defIface != excludedIface {
		if iface, err := net.InterfaceByName(defIface); err == nil &&
			iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			if addrs, err := iface.Addrs(); err == nil {
				for _, a := range addrs {
					var ip net.IP
					if ipn, ok := a.(*net.IPNet); ok {
						ip = ipn.IP
					}
					if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !isExcludedIP(ip) {
						return ip.String()
					}
				}
			}
		}
	}

	// 2. Physical non-Lux interfaces (skip ONLY the Lux TUN interface, preserving corporate VPNs)
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if excludedIface != "" && iface.Name == excludedIface {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			if ipn, ok := a.(*net.IPNet); ok {
				ip = ipn.IP
			}
			if ip == nil || ip.To4() == nil || ip.IsLoopback() || isExcludedIP(ip) {
				continue
			}
			return ip.String()
		}
	}

	// 3. Fallback: dial UDP to outbound target (prefer PAC host if known, else 8.8.8.8)
	var targets []string
	if DefaultRegistry != nil {
		for _, ph := range DefaultRegistry.GetPacHosts() {
			if ipStr := goLookup(ph); ipStr != "" {
				targets = append(targets, ipStr+":80")
			}
		}
	}
	targets = append(targets, "8.8.8.8:53", "1.1.1.1:53")
	for _, t := range targets {
		conn, err := net.DialTimeout("udp", t, 500*time.Millisecond)
		if err == nil {
			defer conn.Close()
			if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
				if !isExcludedIP(udpAddr.IP) && udpAddr.IP.To4() != nil {
					return udpAddr.IP.String()
				}
			}
		}
	}

	return "127.0.0.1"
}

func getMyIP() string {
	myIPMu.RLock()
	cached := myIPCache
	myIPMu.RUnlock()
	if cached != "" {
		return cached
	}
	myIPMu.Lock()
	defer myIPMu.Unlock()
	if myIPCache == "" {
		myIPCache = detectMyIP()
	}
	return myIPCache
}

// ── PAC helper functions ─────────────────────────────────────────────────────

func pacDnsDomainIs(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == domain {
		return true
	}
	if !strings.HasPrefix(domain, ".") {
		return strings.HasSuffix(host, "."+domain)
	}
	return strings.HasSuffix(host, domain)
}

func pacShExpMatch(str, pattern string) bool {
	str = strings.ToLower(str)
	var sb strings.Builder
	sb.WriteString("(?i)^")
	for _, ch := range pattern {
		switch ch {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteString(".")
		case '.', '(', ')', '[', ']', '{', '}', '+', '^', '$', '|', '\\':
			sb.WriteRune('\\')
			sb.WriteRune(ch)
		default:
			sb.WriteRune(ch)
		}
	}
	sb.WriteString("$")
	re, err := regexp.Compile(sb.String())
	if err != nil {
		return false
	}
	return re.MatchString(str)
}

func pacIsInNet(host, pattern, mask string) bool {
	if host == "" || pattern == "" || mask == "" {
		return false
	}
	ipStr := host
	if net.ParseIP(host) == nil {
		ipStr = goLookup(host)
		if ipStr == "" {
			return false
		}
	}
	ip := net.ParseIP(ipStr).To4()
	patIP := net.ParseIP(pattern).To4()
	mskIP := net.ParseIP(mask).To4()
	if ip == nil || patIP == nil || mskIP == nil {
		return false
	}
	for i := 0; i < 4; i++ {
		if ip[i]&mskIP[i] != patIP[i]&mskIP[i] {
			return false
		}
	}
	return true
}

func pacIsPlainHostName(host string) bool {
	return !strings.Contains(host, ".")
}

func pacLocalHostOrDomainIs(host, hostdom string) bool {
	host = strings.ToLower(host)
	hostdom = strings.ToLower(hostdom)
	if host == hostdom {
		return true
	}
	dot := strings.Index(hostdom, ".")
	if dot == -1 {
		return false
	}
	return host == hostdom[:dot]
}

func pacDnsDomainLevels(host string) int {
	return strings.Count(host, ".")
}

func pacIsResolvable(host string) bool {
	return goLookup(host) != ""
}

// ── Time / Date PAC Helpers ──────────────────────────────────────────────────

var weekdayMap = map[string]time.Weekday{
	"SUN": time.Sunday,
	"MON": time.Monday,
	"TUE": time.Tuesday,
	"WED": time.Wednesday,
	"THU": time.Thursday,
	"FRI": time.Friday,
	"SAT": time.Saturday,
}

var monthMap = map[string]int{
	"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
	"JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
}

func evalWeekdayRange(args []goja.Value, now time.Time) bool {
	if len(args) == 0 {
		return false
	}
	useGMT := false
	var strArgs []string
	for _, a := range args {
		s := strings.ToUpper(strings.TrimSpace(a.String()))
		if s == "GMT" {
			useGMT = true
		} else if s != "" {
			strArgs = append(strArgs, s)
		}
	}
	if len(strArgs) == 0 {
		return false
	}
	if useGMT {
		now = now.UTC()
	}
	curW := now.Weekday()

	wd1, ok1 := weekdayMap[strArgs[0]]
	if !ok1 {
		return false
	}
	if len(strArgs) == 1 {
		return curW == wd1
	}

	wd2, ok2 := weekdayMap[strArgs[1]]
	if !ok2 {
		return false
	}
	if wd1 <= wd2 {
		return curW >= wd1 && curW <= wd2
	}
	return curW >= wd1 || curW <= wd2
}

func evalTimeRange(args []goja.Value, now time.Time) bool {
	if len(args) == 0 {
		return false
	}
	useGMT := false
	var nums []int
	for _, a := range args {
		s := strings.ToUpper(strings.TrimSpace(a.String()))
		if s == "GMT" {
			useGMT = true
			continue
		}
		n, err := strconv.Atoi(s)
		if err == nil {
			nums = append(nums, n)
		}
	}
	if len(nums) == 0 {
		return false
	}
	if useGMT {
		now = now.UTC()
	}

	curH, curM, curS := now.Hour(), now.Minute(), now.Second()

	switch len(nums) {
	case 1:
		return curH == nums[0]
	case 2:
		h1, h2 := nums[0], nums[1]
		if h1 <= h2 {
			return curH >= h1 && curH <= h2
		}
		return curH >= h1 || curH <= h2
	case 4:
		t1 := nums[0]*60 + nums[1]
		t2 := nums[2]*60 + nums[3]
		cur := curH*60 + curM
		if t1 <= t2 {
			return cur >= t1 && cur <= t2
		}
		return cur >= t1 || cur <= t2
	case 6:
		t1 := nums[0]*3600 + nums[1]*60 + nums[2]
		t2 := nums[3]*3600 + nums[4]*60 + nums[5]
		cur := curH*3600 + curM*60 + curS
		if t1 <= t2 {
			return cur >= t1 && cur <= t2
		}
		return cur >= t1 || cur <= t2
	}
	return false
}

type dateArgType int

const (
	dateTypeUnknown dateArgType = iota
	dateTypeDay
	dateTypeMonth
	dateTypeYear
)

type parsedDateArg struct {
	kind dateArgType
	val  int
}

func parseDateArg(s string) parsedDateArg {
	s = strings.ToUpper(strings.TrimSpace(s))
	if m, ok := monthMap[s]; ok {
		return parsedDateArg{kind: dateTypeMonth, val: m}
	}
	n, err := strconv.Atoi(s)
	if err == nil {
		if n > 31 {
			return parsedDateArg{kind: dateTypeYear, val: n}
		}
		return parsedDateArg{kind: dateTypeDay, val: n}
	}
	return parsedDateArg{kind: dateTypeUnknown}
}

func evalDateRange(args []goja.Value, now time.Time) bool {
	if len(args) == 0 {
		return false
	}
	useGMT := false
	var parsed []parsedDateArg
	for _, a := range args {
		s := strings.ToUpper(strings.TrimSpace(a.String()))
		if s == "GMT" {
			useGMT = true
			continue
		}
		p := parseDateArg(s)
		if p.kind != dateTypeUnknown {
			parsed = append(parsed, p)
		}
	}
	if len(parsed) == 0 {
		return false
	}
	if useGMT {
		now = now.UTC()
	}

	curYear := now.Year()
	curMonth := int(now.Month())
	curDay := now.Day()

	switch len(parsed) {
	case 1:
		p := parsed[0]
		switch p.kind {
		case dateTypeDay:
			return curDay == p.val
		case dateTypeMonth:
			return curMonth == p.val
		case dateTypeYear:
			return curYear == p.val
		}
	case 2:
		p1, p2 := parsed[0], parsed[1]
		if p1.kind == dateTypeDay && p2.kind == dateTypeDay {
			if p1.val <= p2.val {
				return curDay >= p1.val && curDay <= p2.val
			}
			return curDay >= p1.val || curDay <= p2.val
		}
		if p1.kind == dateTypeMonth && p2.kind == dateTypeMonth {
			if p1.val <= p2.val {
				return curMonth >= p1.val && curMonth <= p2.val
			}
			return curMonth >= p1.val || curMonth <= p2.val
		}
		if p1.kind == dateTypeYear && p2.kind == dateTypeYear {
			return curYear >= p1.val && curYear <= p2.val
		}
		if p1.kind == dateTypeDay && p2.kind == dateTypeMonth {
			return curDay == p1.val && curMonth == p2.val
		}
		if p1.kind == dateTypeMonth && p2.kind == dateTypeYear {
			return curMonth == p1.val && curYear == p2.val
		}
	case 4:
		// day1, month1, day2, month2 OR month1, year1, month2, year2
		if parsed[0].kind == dateTypeDay && parsed[1].kind == dateTypeMonth &&
			parsed[2].kind == dateTypeDay && parsed[3].kind == dateTypeMonth {
			loc := now.Location()
			start := time.Date(curYear, time.Month(parsed[1].val), parsed[0].val, 0, 0, 0, 0, loc)
			end := time.Date(curYear, time.Month(parsed[3].val), parsed[2].val, 23, 59, 59, 0, loc)
			if start.After(end) {
				if now.Before(start) {
					start = start.AddDate(-1, 0, 0)
				} else {
					end = end.AddDate(1, 0, 0)
				}
			}
			return !now.Before(start) && !now.After(end)
		}
		if parsed[0].kind == dateTypeMonth && parsed[1].kind == dateTypeYear &&
			parsed[2].kind == dateTypeMonth && parsed[3].kind == dateTypeYear {
			loc := now.Location()
			start := time.Date(parsed[1].val, time.Month(parsed[0].val), 1, 0, 0, 0, 0, loc)
			end := time.Date(parsed[3].val, time.Month(parsed[2].val)+1, 0, 23, 59, 59, 0, loc)
			return !now.Before(start) && !now.After(end)
		}
	case 6:
		// day1, month1, year1, day2, month2, year2
		loc := now.Location()
		start := time.Date(parsed[2].val, time.Month(parsed[1].val), parsed[0].val, 0, 0, 0, 0, loc)
		end := time.Date(parsed[5].val, time.Month(parsed[4].val), parsed[3].val, 23, 59, 59, 0, loc)
		return !now.Before(start) && !now.After(end)
	}

	return false
}

// ── Goja Runtime Setup ───────────────────────────────────────────────────────

func bindPacHelpers(vm *goja.Runtime) {
	vm.Set("dnsDomainIs", pacDnsDomainIs)
	vm.Set("shExpMatch", pacShExpMatch)
	vm.Set("isInNet", pacIsInNet)
	vm.Set("dnsResolve", func(host string) string { return goLookup(host) })
	vm.Set("myIpAddress", func() string { return getMyIP() })
	vm.Set("myIpAddressEx", func() string { return getMyIP() })
	vm.Set("isPlainHostName", pacIsPlainHostName)
	vm.Set("localHostOrDomainIs", pacLocalHostOrDomainIs)
	vm.Set("dnsDomainLevels", pacDnsDomainLevels)
	vm.Set("isResolvable", pacIsResolvable)
	vm.Set("convert_addr", func(addr string) string { return addr })
	vm.Set("alert", func(call goja.FunctionCall) goja.Value { return goja.Undefined() })

	vm.Set("weekdayRange", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(evalWeekdayRange(call.Arguments, time.Now()))
	})
	vm.Set("dateRange", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(evalDateRange(call.Arguments, time.Now()))
	})
	vm.Set("timeRange", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(evalTimeRange(call.Arguments, time.Now()))
	})
}

// ── CompiledPAC ──────────────────────────────────────────────────────────────

// CompiledPAC holds a compiled JS program and a sync.Pool of pre-initialized
// goja.Runtime VMs ready for evaluation.
type CompiledPAC struct {
	prg   *goja.Program
	rawJS string
	pool  sync.Pool
}

func (c *CompiledPAC) newVM() (*goja.Runtime, error) {
	vm := goja.New()
	bindPacHelpers(vm)
	_, err := vm.RunProgram(c.prg)
	if err != nil {
		return nil, err
	}
	return vm, nil
}

// Compile compiles the PAC JavaScript source via goja.Compile, verifies FindProxyForURL
// exists as a callable function, and initializes the VM pool.
func Compile(js string) (*CompiledPAC, error) {
	prg, err := goja.Compile("pac.js", js, false)
	if err != nil {
		return nil, fmt.Errorf("pac: compile error: %w", err)
	}

	c := &CompiledPAC{
		prg:   prg,
		rawJS: js,
	}
	c.pool.New = func() any {
		vm, err := c.newVM()
		if err != nil {
			log.Warnln("[pac] pool newVM error: %v", err)
			return nil
		}
		return vm
	}

	// Verify FindProxyForURL is present and callable
	testVM, err := c.newVM()
	if err != nil {
		return nil, fmt.Errorf("pac: initialization error: %w", err)
	}
	if _, ok := goja.AssertFunction(testVM.Get("FindProxyForURL")); !ok {
		return nil, fmt.Errorf("pac: FindProxyForURL not found or not a function in script")
	}

	c.pool.Put(testVM)
	return c, nil
}

// Eval evaluates FindProxyForURL(url, host).
// On any error or timeout, returns "DIRECT" (fail-safe).
func (c *CompiledPAC) Eval(url, host string) string {
	res, timedOut := c.EvalRaw(url, host)
	if timedOut || res == "" {
		return "DIRECT"
	}
	return res
}

// EvalRaw evaluates FindProxyForURL(url, host) with a 1500ms timeout.
// Returns ("", true) on timeout so PAC-only outbounds can fail the dial rather
// than silently connecting direct.
func (c *CompiledPAC) EvalRaw(url, host string) (result string, timedOut bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Warnln("[pac] evaluator panic for %s: %v — returning DIRECT", host, r)
			result = "DIRECT"
			timedOut = false
		}
	}()

	v := c.pool.Get()
	if v == nil {
		var err error
		v, err = c.newVM()
		if err != nil {
			log.Warnln("[pac] newVM error for %s: %v", host, err)
			return "DIRECT", false
		}
	}
	vm := v.(*goja.Runtime)

	timer := time.AfterFunc(1500*time.Millisecond, func() {
		vm.Interrupt("pac timeout")
	})
	defer timer.Stop()

	fn, ok := goja.AssertFunction(vm.Get("FindProxyForURL"))
	if !ok {
		log.Warnln("[pac] FindProxyForURL missing during eval for %s", host)
		vm.ClearInterrupt()
		c.pool.Put(vm)
		return "DIRECT", false
	}

	res, err := fn(goja.Undefined(), vm.ToValue(url), vm.ToValue(host))
	if err != nil {
		if strings.Contains(err.Error(), "pac timeout") {
			log.Warnln("[pac] eval timeout for %s", host)
			// Discard interrupted VM so timeout state does not leak to pool
			return "", true
		}
		log.Warnln("[pac] eval error for %s: %v — returning DIRECT", host, err)
		vm.ClearInterrupt()
		c.pool.Put(vm)
		return "DIRECT", false
	}

	vm.ClearInterrupt()
	c.pool.Put(vm)
	return res.String(), false
}

// ── Upstream extraction ──────────────────────────────────────────────────────

var upstreamRe = regexp.MustCompile(`(?i)\b(?:PROXY|HTTP|HTTPS|SOCKS|SOCKS5)\s+([a-zA-Z0-9.\-_]+):(\d+)\b`)

// ExtractUpstreamsFromJS extracts all PROXY|HTTP|HTTPS|SOCKS|SOCKS5 host:port targets declared in js.
func ExtractUpstreamsFromJS(js string) []Directive {
	matches := upstreamRe.FindAllString(js, -1)
	seen := make(map[string]bool)
	var dirs []Directive
	for _, m := range matches {
		for _, d := range ParseDirectives(m) {
			if d.IsDirect() {
				continue
			}
			key := d.Scheme + "|" + d.Host + ":" + d.Port
			if !seen[key] {
				seen[key] = true
				dirs = append(dirs, d)
			}
		}
	}
	return dirs
}

// ExtractUpstreams returns all upstream directives declared in the script.
func (c *CompiledPAC) ExtractUpstreams() []Directive {
	return ExtractUpstreamsFromJS(c.rawJS)
}

// ExtractUpstreamHosts returns unique hostnames of all upstreams declared in the script.
func (c *CompiledPAC) ExtractUpstreamHosts() []string {
	dirs := c.ExtractUpstreams()
	seen := make(map[string]bool)
	var hosts []string
	for _, d := range dirs {
		if d.Host != "" && !seen[d.Host] {
			seen[d.Host] = true
			hosts = append(hosts, d.Host)
		}
	}
	return hosts
}

// ── WPAD helper ──────────────────────────────────────────────────────────────

// ProbeWPADUrl tries to find a PAC URL via OS DHCP option 252, scutil/registry,
// and parallel LAN probes.
func ProbeWPADUrl() string {
	if runtime.GOOS == "darwin" {
		// Fast path: DHCP option 252
		defaultIface := getDefaultIfaceName()
		if defaultIface != "" {
			out, err := exec.Command("ipconfig", "getpacket", defaultIface).Output()
			if err == nil {
				for _, line := range strings.Split(string(out), "\n") {
					if strings.Contains(line, "proxy_auto_discovery_url") {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) == 2 {
							u := strings.TrimSpace(parts[1])
							if strings.HasPrefix(u, "http") {
								log.Infoln("[wpad] found via DHCP option 252: %s", u)
								return u
							}
						}
					}
				}
			}
		}

		// Fast path: scutil --proxy (system proxy config)
		out, err := exec.Command("scutil", "--proxy").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "ProxyAutoConfigURLString") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						u := strings.TrimSpace(parts[1])
						if strings.HasPrefix(u, "http") {
							log.Infoln("[wpad] found via scutil --proxy: %s", u)
							return u
						}
					}
				}
			}
		}

		// Slow path: parallel probes
		var candidates []string
		if defaultIface != "" {
			out2, err2 := exec.Command("ipconfig", "getpacket", defaultIface).Output()
			if err2 == nil {
				for _, line := range strings.Split(string(out2), "\n") {
					if strings.Contains(line, "domain_name") {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) == 2 {
							domain := strings.TrimSpace(parts[1])
							if domain != "" {
								candidates = append(candidates, "http://wpad."+domain+"/wpad.dat")
							}
						}
					}
				}
			}
		}

		if gw := getDefaultGateway(); gw != "" {
			candidates = append(candidates, "http://"+gw+"/wpad.dat")
		}

		if u := probeURLsParallel(candidates); u != "" {
			return u
		}
	}

	if runtime.GOOS == "windows" {
		// Fast path: Windows registry AutoConfigURL
		for _, hive := range []string{"HKCU", "HKLM"} {
			out, err := exec.Command("powershell.exe",
				"-noprofile", "-NonInteractive", "-command",
				fmt.Sprintf(`(Get-ItemProperty "%s:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -EA SilentlyContinue).AutoConfigURL`, hive),
			).Output()
			if err == nil {
				u := strings.TrimSpace(string(out))
				if u != "" && strings.HasPrefix(u, "http") {
					log.Infoln("[wpad] found via Windows registry (%s): %s", hive, u)
					return u
				}
			}
		}

		// Slow path: parallel probes
		candidates := []string{"http://wpad/wpad.dat"}
		if domain := getWindowsDNSSuffix(); domain != "" {
			candidates = append(candidates, "http://wpad."+domain+"/wpad.dat")
		}
		if gw := getDefaultGateway(); gw != "" {
			candidates = append(candidates, "http://"+gw+"/wpad.dat")
		}

		if u := probeURLsParallel(candidates); u != "" {
			return u
		}
	}

	return ""
}

func probeURLsParallel(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}

	type result struct {
		url string
	}
	ch := make(chan result, len(candidates))

	for _, u := range candidates {
		u := u
		go func() {
			if probeURL(u) {
				ch <- result{url: u}
			} else {
				ch <- result{url: ""}
			}
		}()
	}

	for range candidates {
		r := <-ch
		if r.url != "" {
			log.Infoln("[wpad] found via parallel probe: %s", r.url)
			return r.url
		}
	}
	return ""
}

func getDefaultIfaceName() string {
	out, err := exec.Command("route", "get", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	return ""
}

func getDefaultGateway() string {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("powershell.exe",
			"-noprofile", "-NonInteractive", "-command",
			`(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop`,
		).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
	}
	return ""
}

func probeURL(url string) bool {
	client := &http.Client{
		Timeout:   1500 * time.Millisecond,
		Transport: &http.Transport{Proxy: nil},
	}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "FindProxyForURL")
}

func getWindowsDNSSuffix() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	out, err := exec.Command("powershell.exe",
		"-noprofile", "-NonInteractive", "-command",
		`\ = Get-NetIPConfiguration | Where-Object { \.IPv4DefaultGateway } | Select-Object -First 1; if (\) { (Get-DnsClient -InterfaceIndex \.InterfaceIndex -EA SilentlyContinue).ConnectionSpecificSuffix }`,
	).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func NoPacFoundMessage() string {
	if runtime.GOOS == "windows" {
		return "No PAC URL found: registry AutoConfigURL (HKCU and HKLM) is empty, " +
			"and no PAC was served at http://wpad/wpad.dat, wpad.<dns-suffix>, " +
			"or the default gateway."
	}
	return "No PAC URL found: DHCP option 252 is unset and no PAC was served at " +
		"wpad.<domain> or the default gateway."
}
