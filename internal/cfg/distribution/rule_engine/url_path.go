package rule_engine

import (
"strings"

"github.com/igoogolx/itun2socks/internal/constants"
)

// UrlPathRule matches HTTP requests by URL path with an optional method prefix.
//
// Payload format (value field):
//   - "/api/telemetry"          — any method, exact path
//   - "/api/v2/*"               — any method, prefix match (wildcard suffix)
//   - "POST:/api/telemetry"     — POST method, exact path
//   - "GET:/api/v2/*"           — GET method, prefix match
type UrlPathRule struct {
method  string // optional; empty means any method
pattern string // path pattern; trailing "*" enables prefix match
policy  constants.Policy
payload string // original value string for GetPayload()
}

// NewUrlPathRule creates a UrlPathRule from the value and policy strings.
// value format: [METHOD:]PATH[*]
func NewUrlPathRule(value string, policy constants.Policy) (*UrlPathRule, error) {
method := ""
pattern := value

// Extract optional method prefix (e.g. "POST:/api/test")
if idx := strings.Index(value, ":"); idx > 0 {
prefix := value[:idx]
// Only treat as method if it looks like an HTTP method (uppercase letters only)
if isHTTPMethod(prefix) {
method = strings.ToUpper(prefix)
pattern = value[idx+1:]
}
}

return &UrlPathRule{
method:  method,
pattern: pattern,
policy:  policy,
payload: value,
}, nil
}

func isHTTPMethod(s string) bool {
if len(s) == 0 {
return false
}
for _, c := range s {
if c < 'A' || c > 'Z' {
return false
}
}
return true
}

// MatchHTTP implements HTTPRule. Returns false if ctx is nil or not inspected.
func (r *UrlPathRule) MatchHTTP(ctx *HTTPContext) bool {
if ctx == nil || !ctx.Inspected {
return false
}
if ctx.URL == nil {
return false
}

// Check method constraint
if r.method != "" && !strings.EqualFold(ctx.Method, r.method) {
return false
}

path := ctx.URL.Path
if strings.HasSuffix(r.pattern, "*") {
prefix := r.pattern[:len(r.pattern)-1]
return strings.HasPrefix(path, prefix)
}
return path == r.pattern
}

// Match implements Rule — URL-PATH rules are not evaluated via the string path.
// They are only meaningful through MatchHTTP.
func (r *UrlPathRule) Match(_ string) bool { return false }

func (r *UrlPathRule) Value() string               { return r.payload }
func (r *UrlPathRule) GetPolicy() constants.Policy { return r.policy }
func (r *UrlPathRule) Type() constants.RuleType    { return constants.RuleUrlPath }
func (r *UrlPathRule) Valid() bool                 { return r.pattern != "" }
