package rule_engine

import (
"net/http"
"net/url"
"testing"

lru "github.com/hashicorp/golang-lru/v2"
"github.com/igoogolx/itun2socks/internal/constants"
"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/require"
)

var BYPASS_IP = "119.29.29.29"
var BYPASS_DOMAIN = "bing.cn"

var PROXY_IP = "8.8.8.8"
var PROXY_DOMAIN = "google.com"

func TestProxyAll(t *testing.T) {
engine, err := New("proxy_all", []string{})
assert.NoError(t, err)

//not found
_, err = engine.Match(BYPASS_IP, constants.IpRuleTypes)
assert.Equal(t, ErrNotFound, err)

//not found
_, err = engine.Match(BYPASS_DOMAIN, constants.DomainRuleTypes)
assert.Equal(t, ErrNotFound, err)

//not found
_, err = engine.Match(PROXY_IP, constants.IpRuleTypes)
assert.Equal(t, ErrNotFound, err)

//not found
_, err = engine.Match(PROXY_DOMAIN, constants.DomainRuleTypes)
assert.Equal(t, ErrNotFound, err)

}

func TestBypassAll(t *testing.T) {
engine, err := New("bypass_all", []string{})
assert.NoError(t, err)

//bypass
bypassIpRes, err := engine.Match(BYPASS_IP, constants.IpRuleTypes)
assert.NoError(t, err)
assert.Equal(t, bypassIpRes.GetPolicy(), constants.PolicyDirect)

//bypass
bypassDomainRes, err := engine.Match(BYPASS_DOMAIN, constants.DomainRuleTypes)
assert.NoError(t, err)
assert.Equal(t, bypassDomainRes.GetPolicy(), constants.PolicyDirect)

//bypass
proxyIpRes, err := engine.Match(PROXY_IP, constants.IpRuleTypes)
assert.NoError(t, err)
assert.Equal(t, proxyIpRes.GetPolicy(), constants.PolicyDirect)

//bypass
proxyDomainRes, err := engine.Match(PROXY_DOMAIN, constants.DomainRuleTypes)
assert.NoError(t, err)
assert.Equal(t, proxyDomainRes.GetPolicy(), constants.PolicyDirect)
}

func TestBypassCn(t *testing.T) {
engine, err := New("bypass_cn", []string{})
assert.NoError(t, err)

//bypass
bypassIpRes, err := engine.Match(BYPASS_IP, constants.IpRuleTypes)
assert.NoError(t, err)
assert.Equal(t, bypassIpRes.GetPolicy(), constants.PolicyDirect)

//bypass
bypassDomainRes, err := engine.Match(BYPASS_DOMAIN, constants.DomainRuleTypes)
assert.NoError(t, err)
assert.Equal(t, bypassDomainRes.GetPolicy(), constants.PolicyDirect)

//not found
_, err = engine.Match(PROXY_IP, constants.IpRuleTypes)
assert.Equal(t, ErrNotFound, err)

//not found
_, err = engine.Match(PROXY_DOMAIN, constants.DomainRuleTypes)
assert.Equal(t, ErrNotFound, err)

}

func TestProxyGfw(t *testing.T) {
engine, err := New("proxy_gfw", []string{})
assert.NoError(t, err)

//bypass
bypassIpRes, err := engine.Match(BYPASS_IP, constants.IpRuleTypes)
assert.NoError(t, err)
assert.Equal(t, bypassIpRes.GetPolicy(), constants.PolicyDirect)

//bypass
bypassDomainRes, err := engine.Match(BYPASS_DOMAIN, constants.DomainRuleTypes)
assert.NoError(t, err)
assert.Equal(t, bypassDomainRes.GetPolicy(), constants.PolicyDirect)

//bypass
proxyIpRes, err := engine.Match(PROXY_IP, constants.IpRuleTypes)
assert.NoError(t, err)
assert.Equal(t, proxyIpRes.GetPolicy(), constants.PolicyDirect)

//proxy
proxyDomainRes, err := engine.Match(PROXY_DOMAIN, constants.DomainRuleTypes)
assert.NoError(t, err)
assert.Equal(t, proxyDomainRes.GetPolicy(), constants.PolicyProxy)
}

// ---------------------------------------------------------------------------
// Helpers for HTTP rule tests
// ---------------------------------------------------------------------------

// newHTTPEngine builds a minimal Engine from raw extra-rule strings without
// loading any built-in rule file (avoids dependency on embedded rule files
// that may not exist in the test environment).
func newHTTPEngine(t *testing.T, lines []string) *Engine {
t.Helper()
var rules []ParsedRule
for _, line := range lines {
parsed, err := ParseRawValueWithProtocol(line)
require.NoError(t, err, "failed to parse rule: %s", line)
rules = append(rules, parsed)
}
cache, err := lru.New[string, Rule](1024)
require.NoError(t, err)
return &Engine{rules: rules, cache: cache}
}

func makeHTTPCtx(method, rawURL string, headers map[string]string) *HTTPContext {
u, _ := url.Parse(rawURL)
h := http.Header{}
for k, v := range headers {
h.Set(k, v)
}
return &HTTPContext{
Inspected: true,
Method:    method,
URL:       u,
Headers:   h,
}
}

// ---------------------------------------------------------------------------
// TestUrlPathRule_Match
// ---------------------------------------------------------------------------

// Match: any-method exact path
func TestUrlPathRule_Match_ExactPath_AnyMethod(t *testing.T) {
rule, err := NewUrlPathRule("/api/telemetry", constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/api/telemetry", nil)
assert.True(t, rule.MatchHTTP(ctx))
}

// Match: method-constrained path
func TestUrlPathRule_Match_MethodAndPath(t *testing.T) {
rule, err := NewUrlPathRule("POST:/api/data", constants.PolicyReject)
require.NoError(t, err)
ctxPost := makeHTTPCtx("POST", "https://example.com/api/data", nil)
assert.True(t, rule.MatchHTTP(ctxPost))
}

// No-match: wrong method
func TestUrlPathRule_NoMatch_WrongMethod(t *testing.T) {
rule, err := NewUrlPathRule("POST:/api/data", constants.PolicyReject)
require.NoError(t, err)
ctxGet := makeHTTPCtx("GET", "https://example.com/api/data", nil)
assert.False(t, rule.MatchHTTP(ctxGet))
}

// Match: wildcard suffix
func TestUrlPathRule_Match_WildcardSuffix(t *testing.T) {
rule, err := NewUrlPathRule("/api/v2/*", constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/api/v2/users", nil)
assert.True(t, rule.MatchHTTP(ctx))
}

// No-match: path doesn't match pattern
func TestUrlPathRule_NoMatch_DifferentPath(t *testing.T) {
rule, err := NewUrlPathRule("/api/telemetry", constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/other/path", nil)
assert.False(t, rule.MatchHTTP(ctx))
}

// nil ctx: should skip (return false)
func TestUrlPathRule_NilCtx_Skipped(t *testing.T) {
rule, err := NewUrlPathRule("/api/telemetry", constants.PolicyReject)
require.NoError(t, err)
assert.False(t, rule.MatchHTTP(nil))
}

// Non-inspected ctx: should skip (return false)
func TestUrlPathRule_NotInspected_Skipped(t *testing.T) {
rule, err := NewUrlPathRule("/api/telemetry", constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/api/telemetry", nil)
ctx.Inspected = false
assert.False(t, rule.MatchHTTP(ctx))
}

// Parser integration: URL-PATH round-trip
func TestParseItem_UrlPath_RoundTrip(t *testing.T) {
rule, err := ParseItem("URL-PATH", "/api/telemetry", "REJECT")
require.NoError(t, err)
assert.Equal(t, constants.RuleUrlPath, rule.Type())
assert.Equal(t, constants.PolicyReject, rule.GetPolicy())
}

// Parser integration: URL-PATH with method prefix
func TestParseItem_UrlPath_WithMethod(t *testing.T) {
rule, err := ParseItem("URL-PATH", "POST:/api/data", "REJECT")
require.NoError(t, err)
assert.Equal(t, constants.RuleUrlPath, rule.Type())
}

// ---------------------------------------------------------------------------
// TestUrlRegexRule_Match
// ---------------------------------------------------------------------------

// Match: URL matches regex
func TestUrlRegexRule_Match_UrlMatches(t *testing.T) {
rule, err := NewUrlRegexRule(`^https://.*\.google\.com/complete/.*`, constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://www.google.com/complete/search", nil)
assert.True(t, rule.MatchHTTP(ctx))
}

// No-match: URL doesn't match regex
func TestUrlRegexRule_NoMatch_UrlDoesNotMatch(t *testing.T) {
rule, err := NewUrlRegexRule(`^https://.*\.google\.com/complete/.*`, constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/other", nil)
assert.False(t, rule.MatchHTTP(ctx))
}

// nil ctx: should skip
func TestUrlRegexRule_NilCtx_Skipped(t *testing.T) {
rule, err := NewUrlRegexRule(`.*`, constants.PolicyReject)
require.NoError(t, err)
assert.False(t, rule.MatchHTTP(nil))
}

// Non-inspected ctx: should skip
func TestUrlRegexRule_NotInspected_Skipped(t *testing.T) {
rule, err := NewUrlRegexRule(`.*`, constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/path", nil)
ctx.Inspected = false
assert.False(t, rule.MatchHTTP(ctx))
}

// Invalid regex: constructor returns error
func TestUrlRegexRule_InvalidRegex_ReturnsError(t *testing.T) {
_, err := NewUrlRegexRule(`[invalid`, constants.PolicyReject)
assert.Error(t, err)
}

// Parser integration: URL-REGEX round-trip
func TestParseItem_UrlRegex_RoundTrip(t *testing.T) {
rule, err := ParseItem("URL-REGEX", `^https://example\.com/.*`, "PROXY")
require.NoError(t, err)
assert.Equal(t, constants.RuleUrlRegex, rule.Type())
assert.Equal(t, constants.PolicyProxy, rule.GetPolicy())
}

// ---------------------------------------------------------------------------
// TestHeaderRule_Match
// ---------------------------------------------------------------------------

// Match: exact header value
func TestHeaderRule_Match_ExactValue(t *testing.T) {
rule, err := NewHeaderRule("User-Agent:curl/7.88", constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/", map[string]string{
"User-Agent": "curl/7.88",
})
assert.True(t, rule.MatchHTTP(ctx))
}

// Match: wildcard value pattern
func TestHeaderRule_Match_WildcardPattern(t *testing.T) {
rule, err := NewHeaderRule("User-Agent:curl*", constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/", map[string]string{
"User-Agent": "curl/7.88.0",
})
assert.True(t, rule.MatchHTTP(ctx))
}

// Match: case-insensitive header name
func TestHeaderRule_Match_CaseInsensitiveHeaderName(t *testing.T) {
rule, err := NewHeaderRule("user-agent:curl*", constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/", map[string]string{
"User-Agent": "curl/7.88.0",
})
assert.True(t, rule.MatchHTTP(ctx))
}

// No-match: header value doesn't match pattern
func TestHeaderRule_NoMatch_ValueMismatch(t *testing.T) {
rule, err := NewHeaderRule("User-Agent:curl*", constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/", map[string]string{
"User-Agent": "Mozilla/5.0",
})
assert.False(t, rule.MatchHTTP(ctx))
}

// No-match: header not present in request
func TestHeaderRule_NoMatch_HeaderAbsent(t *testing.T) {
rule, err := NewHeaderRule("X-Custom:value", constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/", map[string]string{
"User-Agent": "curl/7.88.0",
})
assert.False(t, rule.MatchHTTP(ctx))
}

// nil ctx: should skip
func TestHeaderRule_NilCtx_Skipped(t *testing.T) {
rule, err := NewHeaderRule("User-Agent:curl*", constants.PolicyReject)
require.NoError(t, err)
assert.False(t, rule.MatchHTTP(nil))
}

// Non-inspected ctx: should skip
func TestHeaderRule_NotInspected_Skipped(t *testing.T) {
rule, err := NewHeaderRule("User-Agent:curl*", constants.PolicyReject)
require.NoError(t, err)
ctx := makeHTTPCtx("GET", "https://example.com/", map[string]string{
"User-Agent": "curl/7.88.0",
})
ctx.Inspected = false
assert.False(t, rule.MatchHTTP(ctx))
}

// Malformed payload (no colon): constructor returns error
func TestHeaderRule_MalformedPayload_ReturnsError(t *testing.T) {
_, err := NewHeaderRule("UserAgentcurl", constants.PolicyReject)
assert.Error(t, err)
}

// Parser integration: HEADER round-trip
func TestParseItem_Header_RoundTrip(t *testing.T) {
rule, err := ParseItem("HEADER", "User-Agent:curl*", "REJECT")
require.NoError(t, err)
assert.Equal(t, constants.RuleHeader, rule.Type())
assert.Equal(t, constants.PolicyReject, rule.GetPolicy())
}

// ---------------------------------------------------------------------------
// MatchHTTPContext engine integration tests
// ---------------------------------------------------------------------------

// MatchHTTPContext returns the first matching HTTP rule
func TestEngine_MatchHTTPContext_Match(t *testing.T) {
engine := newHTTPEngine(t, []string{
"URL-PATH,/api/telemetry,REJECT",
})
ctx := makeHTTPCtx("GET", "https://example.com/api/telemetry", nil)
rule, err := engine.MatchHTTPContext(ctx)
require.NoError(t, err)
assert.Equal(t, constants.PolicyReject, rule.GetPolicy())
}

// MatchHTTPContext returns ErrNotFound when no HTTP rule matches
func TestEngine_MatchHTTPContext_NoMatch(t *testing.T) {
engine := newHTTPEngine(t, []string{
"URL-PATH,/api/telemetry,REJECT",
})
ctx := makeHTTPCtx("GET", "https://example.com/other/path", nil)
_, err := engine.MatchHTTPContext(ctx)
assert.ErrorIs(t, err, ErrNotFound)
}

// MatchHTTPContext returns ErrNotFound when ctx is nil
func TestEngine_MatchHTTPContext_NilCtx(t *testing.T) {
engine := newHTTPEngine(t, []string{
"URL-PATH,/api/telemetry,REJECT",
})
_, err := engine.MatchHTTPContext(nil)
assert.ErrorIs(t, err, ErrNotFound)
}

// MatchHTTPContext returns ErrNotFound when Inspected is false
func TestEngine_MatchHTTPContext_NotInspected(t *testing.T) {
engine := newHTTPEngine(t, []string{
"URL-PATH,/api/telemetry,REJECT",
})
ctx := makeHTTPCtx("GET", "https://example.com/api/telemetry", nil)
ctx.Inspected = false
_, err := engine.MatchHTTPContext(ctx)
assert.ErrorIs(t, err, ErrNotFound)
}
