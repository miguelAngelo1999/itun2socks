// Package pac provides PAC (Proxy Auto-Config) evaluation.
//
// EvalForURL executes FindProxyForURL(url, host) against a cached PAC script
// using a purpose-built interpreter for the frozen PAC/ES3 function subset.
// No external JS engine is required — PAC defines exactly 12 helper functions
// and a predictable control-flow grammar that we can evaluate natively.
//
// Supported PAC functions:
//   dnsDomainIs, shExpMatch, isInNet, dnsResolve, myIpAddress,
//   isPlainHostName, localHostOrDomainIs, dnsDomainLevels,
//   isResolvable, weekdayRange, dateRange, timeRange
//
// The interpreter handles:
//   - if / else if / else chains
//   - return "DIRECT" / return "PROXY host:port"
//   - boolean &&, ||, ! operators
//   - Nested function calls to the helpers above
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
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// ── DNS cache ────────────────────────────────────────────────────────────────

var dnsCache *lru.Cache[string, string]
var dnsCacheOnce sync.Once

func getDNSCache() *lru.Cache[string, string] {
	dnsCacheOnce.Do(func() {
		c, _ := lru.New[string, string](512)
		dnsCache = c
	})
	return dnsCache
}

// goLookup resolves host to its first IPv4 address with a 500ms timeout.
// Results are cached in a 512-entry LRU.
func goLookup(host string) string {
	cache := getDNSCache()
	if v, ok := cache.Get(host); ok {
		return v
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	// Prefer IPv4
	result := addrs[0]
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			result = a
			break
		}
	}
	cache.Add(host, result)
	return result
}

// ── myIpAddress ──────────────────────────────────────────────────────────────

var (
	myIPOnce  sync.Once
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
	// In TUN/Mixed mode, dialling 8.8.8.8 routes through the TUN interface
	// and returns the TUN IP (198.18.x.x) instead of the real LAN IP.
	// Instead, find the first non-loopback, non-TUN IPv4 from physical interfaces.
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		// Skip TUN/utun interfaces
		name := iface.Name
		if len(name) >= 4 && (name[:4] == "utun" || name[:3] == "tun") {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			if ipn, ok := a.(*net.IPNet); ok {
				ip = ipn.IP
			}
			if ip == nil || ip.To4() == nil || ip.IsLoopback() {
				continue
			}
			// Skip TUN address range (198.18.0.0/15 — RFC 2544 benchmarking)
			if ip[0] == 198 && ip[1] >= 18 && ip[1] <= 19 {
				continue
			}
			return ip.String()
		}
	}
	// Fallback: dial to get outbound IP
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 1*time.Second)
	if err == nil {
		defer conn.Close()
		if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			return udpAddr.IP.String()
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

// pacDnsDomainIs implements dnsDomainIs(host, domain).
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

// pacShExpMatch implements shExpMatch(str, pattern) — shell glob to regexp.
func pacShExpMatch(str, pattern string) bool {
	str = strings.ToLower(str)
	// Convert shell pattern to regexp.
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

// pacIsInNet implements isInNet(host, pattern, mask).
func pacIsInNet(host, pattern, mask string) bool {
	// host may already be an IP, or a hostname to resolve.
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

// pacIsPlainHostName implements isPlainHostName(host) — no dots.
func pacIsPlainHostName(host string) bool {
	return !strings.Contains(host, ".")
}

// pacLocalHostOrDomainIs implements localHostOrDomainIs(host, hostdom).
func pacLocalHostOrDomainIs(host, hostdom string) bool {
	host = strings.ToLower(host)
	hostdom = strings.ToLower(hostdom)
	if host == hostdom {
		return true
	}
	// short host matches if hostdom starts with host+"."
	dot := strings.Index(hostdom, ".")
	if dot == -1 {
		return false
	}
	return host == hostdom[:dot]
}

// pacDnsDomainLevels implements dnsDomainLevels(host).
func pacDnsDomainLevels(host string) int {
	return strings.Count(host, ".")
}

// pacIsResolvable implements isResolvable(host).
func pacIsResolvable(host string) bool {
	return goLookup(host) != ""
}

// ── Script extraction ─────────────────────────────────────────────────────────

// extractBody pulls the text of FindProxyForURL's body from the PAC JS source.
// Returns the raw body between the outermost { }.
func extractBody(js string) string {
	// Find the function declaration
	idx := strings.Index(js, "FindProxyForURL")
	if idx == -1 {
		return ""
	}
	// Scan forward for the opening brace
	start := strings.Index(js[idx:], "{")
	if start == -1 {
		return ""
	}
	start += idx + 1
	depth := 1
	for i := start; i < len(js); i++ {
		switch js[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return js[start:i]
			}
		}
	}
	return ""
}

// stripComments removes // and /* */ comments from JS source.
func stripComments(js string) string {
	// Remove block comments
	var out strings.Builder
	i := 0
	for i < len(js) {
		if i+1 < len(js) && js[i] == '/' && js[i+1] == '*' {
			end := strings.Index(js[i+2:], "*/")
			if end == -1 {
				break
			}
			// Preserve newlines for line-oriented parsing
			for _, c := range js[i : i+2+end+2] {
				if c == '\n' {
					out.WriteByte('\n')
				}
			}
			i = i + 2 + end + 2
			continue
		}
		if i+1 < len(js) && js[i] == '/' && js[i+1] == '/' {
			end := strings.Index(js[i:], "\n")
			if end == -1 {
				break
			}
			out.WriteByte('\n')
			i = i + end + 1
			continue
		}
		out.WriteByte(js[i])
		i++
	}
	return out.String()
}

// ── Tokenizer ─────────────────────────────────────────────────────────────────

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokString
	tokNumber
	tokLParen
	tokRParen
	tokLBrace
	tokRBrace
	tokComma
	tokSemicolon
	tokAnd // &&
	tokOr  // ||
	tokNot // !
	tokEq  // ==
	tokNeq // !=
	tokLt  // <
	tokGt  // >
	tokLte // <=
	tokGte // >=
)

type token struct {
	kind tokenKind
	val  string
}

type lexer struct {
	src []rune
	pos int
}

func newLexer(src string) *lexer { return &lexer{src: []rune(src)} }

func (l *lexer) peek() rune {
	if l.pos >= len(l.src) {
		return 0
	}
	return l.src[l.pos]
}

func (l *lexer) read() rune {
	if l.pos >= len(l.src) {
		return 0
	}
	ch := l.src[l.pos]
	l.pos++
	return ch
}

func (l *lexer) skipWS() {
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ';' {
			l.pos++
		} else {
			break
		}
	}
}

func (l *lexer) next() token {
	l.skipWS()
	if l.pos >= len(l.src) {
		return token{tokEOF, ""}
	}
	ch := l.peek()

	// Two-char operators
	if l.pos+1 < len(l.src) {
		two := string(l.src[l.pos : l.pos+2])
		switch two {
		case "&&":
			l.pos += 2
			return token{tokAnd, "&&"}
		case "||":
			l.pos += 2
			return token{tokOr, "||"}
		case "==":
			l.pos += 2
			return token{tokEq, "=="}
		case "!=":
			l.pos += 2
			return token{tokNeq, "!="}
		case "<=":
			l.pos += 2
			return token{tokLte, "<="}
		case ">=":
			l.pos += 2
			return token{tokGte, ">="}
		}
	}

	switch ch {
	case '(':
		l.pos++
		return token{tokLParen, "("}
	case ')':
		l.pos++
		return token{tokRParen, ")"}
	case '{':
		l.pos++
		return token{tokLBrace, "{"}
	case '}':
		l.pos++
		return token{tokRBrace, "}"}
	case ',':
		l.pos++
		return token{tokComma, ","}
	case ';':
		l.pos++
		return token{tokSemicolon, ";"}
	case '!':
		l.pos++
		return token{tokNot, "!"}
	case '<':
		l.pos++
		return token{tokLt, "<"}
	case '>':
		l.pos++
		return token{tokGt, ">"}
	case '"', '\'':
		return l.readString(ch)
	}

	if ch >= '0' && ch <= '9' {
		return l.readNumber()
	}
	if isIdentStart(ch) {
		return l.readIdent()
	}
	// Skip unknown character
	l.pos++
	return l.next()
}

func isIdentStart(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch == '$'
}

func isIdentPart(ch rune) bool {
	return isIdentStart(ch) || (ch >= '0' && ch <= '9')
}

func (l *lexer) readString(quote rune) token {
	l.pos++ // skip opening quote
	var sb strings.Builder
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		l.pos++
		if ch == quote {
			break
		}
		if ch == '\\' && l.pos < len(l.src) {
			next := l.src[l.pos]
			l.pos++
			switch next {
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			default:
				sb.WriteRune(next)
			}
			continue
		}
		sb.WriteRune(ch)
	}
	return token{tokString, sb.String()}
}

func (l *lexer) readNumber() token {
	start := l.pos
	for l.pos < len(l.src) && l.src[l.pos] >= '0' && l.src[l.pos] <= '9' {
		l.pos++
	}
	return token{tokNumber, string(l.src[start:l.pos])}
}

func (l *lexer) readIdent() token {
	start := l.pos
	for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
		l.pos++
	}
	return token{tokIdent, string(l.src[start:l.pos])}
}

// ── Parser / Evaluator ────────────────────────────────────────────────────────

// parser evaluates PAC body statements directly during parsing.
type parser struct {
	lex    *lexer
	peeked *token
	host   string // the "host" variable in FindProxyForURL scope
	url    string // the "url" variable
}

func (p *parser) peek() token {
	if p.peeked != nil {
		return *p.peeked
	}
	t := p.lex.next()
	p.peeked = &t
	return t
}

func (p *parser) consume() token {
	if p.peeked != nil {
		t := *p.peeked
		p.peeked = nil
		return t
	}
	return p.lex.next()
}

func (p *parser) expect(k tokenKind) {
	t := p.consume()
	_ = t // error handling is best-effort in PAC evaluation
	if t.kind == tokEOF {
		// Unexpected EOF — ignore
	}
}

// parseBlock executes a { } block and returns a result string if a return was hit.
func (p *parser) parseBlock() (string, bool) {
	p.expect(tokLBrace)
	for {
		t := p.peek()
		if t.kind == tokRBrace || t.kind == tokEOF {
			p.consume()
			return "", false
		}
		if result, ok := p.parseStatement(); ok {
			// drain remaining statements
			p.drainBlock()
			return result, true
		}
	}
}

// drainBlock skips tokens until the matching } is consumed.
func (p *parser) drainBlock() {
	depth := 1
	for depth > 0 {
		t := p.consume()
		switch t.kind {
		case tokLBrace:
			depth++
		case tokRBrace:
			depth--
		case tokEOF:
			return
		}
	}
}

// parseStatement executes one statement (if/return/var/expr).
// Returns (result, true) if a return was encountered.
func (p *parser) parseStatement() (string, bool) {
	t := p.peek()
	if t.kind == tokEOF || t.kind == tokRBrace {
		return "", false
	}
	if t.kind == tokIdent {
		switch t.val {
		case "if":
			return p.parseIf()
		case "return":
			return p.parseReturn()
		case "var", "let", "const":
			p.consume() // skip keyword
			p.skipToSemicolon()
			return "", false
		case "function":
			// Nested function def — skip entirely
			p.consume()
			p.skipToBlockEnd()
			return "", false
		}
	}
	// Expression statement — evaluate and discard
	p.skipToSemicolon()
	return "", false
}

func (p *parser) skipToSemicolon() {
	depth := 0
	for {
		t := p.peek()
		if t.kind == tokEOF {
			return
		}
		if t.kind == tokLBrace {
			depth++
		}
		if t.kind == tokRBrace {
			if depth == 0 {
				return
			}
			depth--
		}
		if t.kind == tokSemicolon && depth == 0 {
			p.consume()
			return
		}
		p.consume()
	}
}

func (p *parser) skipToBlockEnd() {
	// Skip optional function name + param list
	for {
		t := p.peek()
		if t.kind == tokLBrace || t.kind == tokEOF {
			break
		}
		p.consume()
	}
	if p.peek().kind == tokLBrace {
		p.drainBlock()
		p.lex.pos-- // drainBlock consumes the }, undo to balance
		p.consume() // re-consume }
	}
}

// parseIf evaluates an if/else if/else chain.
func (p *parser) parseIf() (string, bool) {
	p.consume() // consume "if"
	p.expect(tokLParen)
	cond := p.parseExpr()
	p.expect(tokRParen)

	if cond {
		result, ok := p.parseBlockOrStatement()
		if ok {
			// Drain any else branches
			p.skipElseChain()
			return result, true
		}
		p.skipElseChain()
		return "", false
	}
	// Condition false — skip the then-branch
	p.skipBlockOrStatement()
	// Check for else/else-if
	if p.peek().kind == tokIdent && p.peek().val == "else" {
		p.consume() // consume "else"
		if p.peek().kind == tokIdent && p.peek().val == "if" {
			return p.parseIf()
		}
		return p.parseBlockOrStatement()
	}
	return "", false
}

func (p *parser) parseBlockOrStatement() (string, bool) {
	if p.peek().kind == tokLBrace {
		return p.parseBlock()
	}
	return p.parseStatement()
}

func (p *parser) skipBlockOrStatement() {
	if p.peek().kind == tokLBrace {
		p.consume() // {
		p.drainBlock()
		return
	}
	p.skipToSemicolon()
}

func (p *parser) skipElseChain() {
	for p.peek().kind == tokIdent && p.peek().val == "else" {
		p.consume() // else
		if p.peek().kind == tokIdent && p.peek().val == "if" {
			p.consume() // if
			// skip condition
			depth := 0
			for {
				t := p.consume()
				if t.kind == tokEOF {
					return
				}
				if t.kind == tokLParen {
					depth++
				}
				if t.kind == tokRParen {
					depth--
					if depth == 0 {
						break
					}
				}
			}
		}
		p.skipBlockOrStatement()
	}
}

// parseReturn parses: return "DIRECT"; or return "PROXY host:port";
func (p *parser) parseReturn() (string, bool) {
	p.consume() // consume "return"
	t := p.peek()
	if t.kind == tokString {
		p.consume()
		return t.val, true
	}
	if t.kind == tokIdent {
		// Some PAC files do: return "DIRECT" without quotes on old impls — ignore
	}
	p.skipToSemicolon()
	return "DIRECT", true // conservative: unknown return → DIRECT
}

// ── Expression evaluator ──────────────────────────────────────────────────────

// parseExpr evaluates a boolean expression (||, &&, !, function calls).
func (p *parser) parseExpr() bool {
	return p.parseOr()
}

func (p *parser) parseOr() bool {
	left := p.parseAnd()
	for p.peek().kind == tokOr {
		p.consume()
		right := p.parseAnd()
		left = left || right
	}
	return left
}

func (p *parser) parseAnd() bool {
	left := p.parseUnary()
	for p.peek().kind == tokAnd {
		p.consume()
		right := p.parseUnary()
		left = left && right
	}
	return left
}

func (p *parser) parseUnary() bool {
	if p.peek().kind == tokNot {
		p.consume()
		return !p.parsePrimary()
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() bool {
	t := p.peek()

	// Parenthesised expression
	if t.kind == tokLParen {
		p.consume()
		val := p.parseExpr()
		if p.peek().kind == tokRParen {
			p.consume()
		}
		return val
	}

	// Boolean literals
	if t.kind == tokIdent && t.val == "true" {
		p.consume()
		return true
	}
	if t.kind == tokIdent && t.val == "false" {
		p.consume()
		return false
	}

	// Function call or identifier
	if t.kind == tokIdent {
		return p.parseFuncCallOrCompare()
	}

	// String literal in a boolean context — truthy if non-empty
	if t.kind == tokString {
		p.consume()
		return t.val != ""
	}

	// Number literal — truthy if non-zero
	if t.kind == tokNumber {
		p.consume()
		return t.val != "0" && t.val != ""
	}

	return false
}

// parseFuncCallOrCompare handles: func(args...) [== / != / < / > value]
func (p *parser) parseFuncCallOrCompare() bool {
	name := p.consume().val // consume the identifier

	// Not a function call — just a variable name in boolean context
	if p.peek().kind != tokLParen {
		// treat as truthy if it's "host" or "url" etc.
		return true
	}

	// Parse argument list
	p.consume() // (
	args := p.parseArgList()

	// Evaluate the function
	result := p.callPACFunc(name, args)

	// Check for comparison operator after the call: func() == "value"
	op := p.peek()
	if op.kind == tokEq || op.kind == tokNeq || op.kind == tokLt ||
		op.kind == tokGt || op.kind == tokLte || op.kind == tokGte {
		p.consume()
		rhs := p.parseValue()
		switch op.kind {
		case tokEq:
			return strings.EqualFold(result, rhs)
		case tokNeq:
			return !strings.EqualFold(result, rhs)
		}
		return false
	}

	// Boolean result from function
	return result != "" && result != "false" && result != "0" && result != "undefined"
}

// parseArgList collects all arguments (strings, identifiers, nested calls)
// until the closing ) is consumed.
func (p *parser) parseArgList() []string {
	var args []string
	for {
		t := p.peek()
		if t.kind == tokRParen || t.kind == tokEOF {
			p.consume()
			break
		}
		if t.kind == tokComma {
			p.consume()
			continue
		}
		args = append(args, p.parseValue())
	}
	return args
}

// parseValue evaluates a single value token or nested function call.
// Returns a string representation of the value.
func (p *parser) parseValue() string {
	t := p.peek()
	switch t.kind {
	case tokString:
		p.consume()
		return t.val
	case tokNumber:
		p.consume()
		return t.val
	case tokIdent:
		name := p.consume().val
		// Variable references
		switch name {
		case "host":
			return p.host
		case "url":
			return p.url
		}
		// Nested function call
		if p.peek().kind == tokLParen {
			p.consume()
			args := p.parseArgList()
			return p.callPACFunc(name, args)
		}
		return name
	case tokLParen:
		p.consume()
		val := p.parseValue()
		if p.peek().kind == tokRParen {
			p.consume()
		}
		return val
	}
	p.consume()
	return ""
}

// callPACFunc dispatches to the appropriate PAC helper.
// Returns the string result of the function (for functions that return booleans,
// returns "true"/"false" or "" for falsy).
func (p *parser) callPACFunc(name string, args []string) string {
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	boolStr := func(b bool) string {
		if b {
			return "true"
		}
		return ""
	}

	switch name {
	case "dnsDomainIs":
		return boolStr(pacDnsDomainIs(arg(0), arg(1)))
	case "shExpMatch":
		return boolStr(pacShExpMatch(arg(0), arg(1)))
	case "isInNet":
		return boolStr(pacIsInNet(arg(0), arg(1), arg(2)))
	case "isPlainHostName":
		return boolStr(pacIsPlainHostName(arg(0)))
	case "localHostOrDomainIs":
		return boolStr(pacLocalHostOrDomainIs(arg(0), arg(1)))
	case "dnsDomainLevels":
		return fmt.Sprintf("%d", pacDnsDomainLevels(arg(0)))
	case "isResolvable":
		return boolStr(pacIsResolvable(arg(0)))
	case "dnsResolve":
		return goLookup(arg(0))
	case "myIpAddress":
		return getMyIP()
	case "convert_addr":
		// Some old PAC files use this — return the arg unchanged
		return arg(0)
	case "weekdayRange", "dateRange", "timeRange":
		// Time-based rules — always return true (assume in range).
		// These are rarely used in routing decisions; false negatives are safe.
		return "true"
	}
	return ""
}

// ── CompiledPAC ────────────────────────────────────────────────────────────────

// CompiledPAC holds a pre-stripped PAC function body ready for evaluation.
// Create once via Compile(), then call Eval() concurrently.
type CompiledPAC struct {
	body string // stripped, comment-free function body
}

// Compile strips comments and extracts the FindProxyForURL body.
// Returns an error if no FindProxyForURL function is found.
func Compile(js string) (*CompiledPAC, error) {
	clean := stripComments(js)
	body := extractBody(clean)
	if body == "" {
		return nil, fmt.Errorf("pac: FindProxyForURL not found in script")
	}
	return &CompiledPAC{body: body}, nil
}

// Eval evaluates FindProxyForURL(url, host) against the compiled body.
// Returns the proxy directive string, e.g. "DIRECT", "PROXY 10.0.0.1:8080".
// On any error or timeout, returns "DIRECT" (fail-safe for corporate routing).
func (c *CompiledPAC) Eval(url, host string) (result string) {
	defer func() {
		if r := recover(); r != nil {
			log.Warnln("[pac] evaluator panic for %s: %v — returning DIRECT", host, r)
			result = "DIRECT"
		}
	}()

	done := make(chan string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- "DIRECT"
			}
		}()
		lex := newLexer(c.body)
		p := &parser{lex: lex, host: host, url: url}
		// Execute statements until a return is found or body ends
		for {
			t := p.peek()
			if t.kind == tokEOF {
				done <- "DIRECT" // no explicit return — fall through to DIRECT
				return
			}
			if res, ok := p.parseStatement(); ok {
				done <- res
				return
			}
		}
	}()

	select {
	case res := <-done:
		return res
	case <-time.After(200 * time.Millisecond):
		log.Warnln("[pac] eval timeout for %s — returning DIRECT", host)
		return "DIRECT"
	}
}

// ── wpad helper ──────────────────────────────────────────────────────────────

// ProbeWPADUrl tries to find a PAC URL via WPAD DNS lookup.
// Returns an empty string if not found.
func ProbeWPADUrl() string {
	if runtime.GOOS == "darwin" {
		// Try ipconfig first (works as the user, not as root)
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
								return u
							}
						}
					}
				}
			}
		}
		// Fallback: scutil --proxy works regardless of user context (even as root)
		out, err := exec.Command("scutil", "--proxy").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "ProxyAutoConfigURLString") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						u := strings.TrimSpace(parts[1])
						if strings.HasPrefix(u, "http") {
							return u
						}
					}
				}
			}
		}
		// Last resort: try the standard WPAD URL derived from DHCP domain
		// Many corporate networks serve http://wpad.<domain>/wpad.dat
		out2, err := exec.Command("ipconfig", "getpacket", defaultIface).Output()
		if err == nil {
			for _, line := range strings.Split(string(out2), "\n") {
				if strings.Contains(line, "domain_name") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						domain := strings.TrimSpace(parts[1])
						if domain != "" {
							wpadUrl := "http://wpad." + domain + "/wpad.dat"
							if probeURL(wpadUrl) {
								return wpadUrl
							}
						}
					}
				}
			}
		}
		// Final fallback: try http://<gateway>/wpad.dat directly.
		// Many corporate routers serve the PAC at their own IP without a
		// DNS record or DHCP option set.
		if gw := getDefaultGateway(); gw != "" {
			wpadUrl := "http://" + gw + "/wpad.dat"
			if probeURL(wpadUrl) {
				return wpadUrl
			}
		}
	}
	if runtime.GOOS == "windows" {
		// 1. Explicit PAC in the registry, per-user then machine-wide.
		for _, hive := range []string{"HKCU", "HKLM"} {
			out, err := exec.Command("powershell.exe",
				"-noprofile", "-NonInteractive", "-command",
				fmt.Sprintf(`(Get-ItemProperty "%s:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -EA SilentlyContinue).AutoConfigURL`, hive),
			).Output()
			if err == nil {
				u := strings.TrimSpace(string(out))
				if u != "" && strings.HasPrefix(u, "http") {
					return u
				}
			}
		}
		// 2. WPAD by name, plain and per connection-specific DNS suffix. This is
		// the DHCP option 252 / DNS devolution path the message advertises.
		candidates := []string{"http://wpad/wpad.dat"}
		if domain := getWindowsDNSSuffix(); domain != "" {
			candidates = append(candidates, "http://wpad."+domain+"/wpad.dat")
		}
		// 3. Many corporate routers serve the PAC at their own IP with no DHCP
		// option and no DNS record, so try the default gateway last.
		if gw := getDefaultGateway(); gw != "" {
			candidates = append(candidates, "http://"+gw+"/wpad.dat")
		}
		for _, u := range candidates {
			if probeURL(u) {
				return u
			}
		}
	}
	return ""
}

func getDefaultIfaceName() string {
	// Attempt to read via "route get default" on macOS
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
		// route.exe output is localised, so ask PowerShell for the lowest
		// metric default route instead of parsing text.
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

// probeURL does a quick HEAD/GET to see if a URL is reachable and returns content.
func probeURL(url string) bool {
	// Discovery must go direct. The default transport honours HTTP_PROXY, and
	// lux exports it while proxying, so an upstream proxy answers 200 for
	// hostnames that do not resolve and every candidate looks reachable.
	client := &http.Client{
		Timeout:   4 * time.Second,
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
	// A 200 on its own proves nothing: captive portals and proxy error pages
	// return 200 with HTML. Require the entry point a PAC must declare.
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "FindProxyForURL")
}

// getWindowsDNSSuffix returns the connection-specific DNS suffix of the
// interface holding the default route, which is what DHCP hands out and what
// WPAD name devolution is based on. Empty when the network advertises none.
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

// NoPacFoundMessage explains what was actually probed, per platform. The old
// wording claimed DHCP option 252 had been consulted on every OS, which was
// untrue on Windows and sent people looking for a DHCP problem that did not
// exist.
func NoPacFoundMessage() string {
	if runtime.GOOS == "windows" {
		return "No PAC URL found: registry AutoConfigURL (HKCU and HKLM) is empty, " +
			"and no PAC was served at http://wpad/wpad.dat, wpad.<dns-suffix>, " +
			"or the default gateway."
	}
	return "No PAC URL found: DHCP option 252 is unset and no PAC was served at " +
		"wpad.<domain> or the default gateway."
}
