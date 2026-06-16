package rule_engine

import (
"fmt"
"regexp"

"github.com/igoogolx/itun2socks/internal/constants"
)

// UrlRegexRule matches HTTP requests by testing the full URL string against a regexp.
type UrlRegexRule struct {
re         *regexp.Regexp
rawPattern string
policy     constants.Policy
}

// NewUrlRegexRule compiles the regex pattern and returns a UrlRegexRule.
func NewUrlRegexRule(value string, policy constants.Policy) (*UrlRegexRule, error) {
re, err := regexp.Compile(value)
if err != nil {
return nil, fmt.Errorf("URL-REGEX: invalid pattern %q: %w", value, err)
}
return &UrlRegexRule{
re:         re,
rawPattern: value,
policy:     policy,
}, nil
}

// MatchHTTP implements HTTPRule. Returns false if ctx is nil or not inspected.
func (r *UrlRegexRule) MatchHTTP(ctx *HTTPContext) bool {
if ctx == nil || !ctx.Inspected {
return false
}
if ctx.URL == nil {
return false
}
return r.re.MatchString(ctx.URL.String())
}

// Match implements Rule — URL-REGEX rules use MatchHTTP, not string matching.
func (r *UrlRegexRule) Match(_ string) bool { return false }

func (r *UrlRegexRule) Value() string               { return r.rawPattern }
func (r *UrlRegexRule) GetPolicy() constants.Policy { return r.policy }
func (r *UrlRegexRule) Type() constants.RuleType    { return constants.RuleUrlRegex }
func (r *UrlRegexRule) Valid() bool                 { return r.re != nil }
