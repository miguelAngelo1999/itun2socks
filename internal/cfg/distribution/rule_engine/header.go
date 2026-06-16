package rule_engine

import (
"fmt"
"strings"

"github.com/igoogolx/itun2socks/internal/constants"
)

// HeaderRule matches HTTP requests by header name and an optional glob pattern
// on the header value.
//
// Payload format: "Header-Name:value_pattern"
//   - "User-Agent:curl*"    – match requests whose User-Agent starts with "curl"
//   - "X-Custom:exact"      – exact value match
//   - "Accept:*"            – header present with any value
//
// Header name lookup is case-insensitive.
// Value pattern supports "*" as a wildcard (glob).
type HeaderRule struct {
headerName   string
valuePattern string
payload      string
policy       constants.Policy
}

// Match always returns false; HTTP rules use MatchHTTP.
func (r *HeaderRule) Match(_ string) bool { return false }

// MatchHTTP returns true when ctx carries an inspected request that has a
// header matching headerName whose value satisfies valuePattern.
func (r *HeaderRule) MatchHTTP(ctx *HTTPContext) bool {
if ctx == nil || !ctx.Inspected {
return false
}
// Case-insensitive header name lookup.
for name, values := range ctx.Headers {
if !strings.EqualFold(name, r.headerName) {
continue
}
for _, v := range values {
if globMatch(r.valuePattern, v) {
return true
}
}
}
return false
}

func (r *HeaderRule) GetPolicy() constants.Policy { return r.policy }
func (r *HeaderRule) Type() constants.RuleType     { return constants.RuleHeader }
func (r *HeaderRule) Value() string                { return r.payload }
func (r *HeaderRule) Valid() bool                  { return len(r.headerName) > 0 }

// NewHeaderRule parses "Header-Name:value_pattern" into a HeaderRule.
func NewHeaderRule(payload string, policy constants.Policy) (*HeaderRule, error) {
if len(payload) == 0 {
return nil, fmt.Errorf("header rule: empty payload")
}
idx := strings.Index(payload, ":")
if idx <= 0 {
return nil, fmt.Errorf("header rule: payload must be in format Name:pattern, got %q", payload)
}
name := strings.TrimSpace(payload[:idx])
pattern := payload[idx+1:]
if len(name) == 0 {
return nil, fmt.Errorf("header rule: empty header name")
}
return &HeaderRule{
headerName:   name,
valuePattern: pattern,
payload:      payload,
policy:       policy,
}, nil
}

// globMatch reports whether s matches the glob pattern p.
// Only "*" wildcards are supported (matches any sequence of characters).
func globMatch(pattern, s string) bool {
// Fast paths.
if pattern == "*" {
return true
}
if !strings.Contains(pattern, "*") {
return pattern == s
}
// Split on "*" and match segments in order.
parts := strings.Split(pattern, "*")
pos := 0
for i, part := range parts {
if len(part) == 0 {
continue
}
idx := strings.Index(s[pos:], part)
if idx == -1 {
return false
}
// The first segment must match at the start.
if i == 0 && idx != 0 {
return false
}
pos += idx + len(part)
}
// If the pattern does not end with "*", the last segment must reach the end.
if !strings.HasSuffix(pattern, "*") {
return strings.HasSuffix(s, parts[len(parts)-1])
}
return true
}