package mitm

import (
"testing"
)

// TestInspectionList_ExactMatch verifies that an exact domain pattern is matched.
func TestInspectionList_ExactMatch(t *testing.T) {
il := NewInspectionList()
il.Add("example.com")

if !il.Contains("example.com") {
t.Error("expected Contains(example.com) = true for exact match, got false")
}
if il.Contains("sub.example.com") {
t.Error("expected Contains(sub.example.com) = false for exact pattern, got true")
}
if il.Contains("notexample.com") {
t.Error("expected Contains(notexample.com) = false, got true")
}
}

// TestInspectionList_WildcardMatch verifies that *.example.com matches subdomains.
func TestInspectionList_WildcardMatch(t *testing.T) {
il := NewInspectionList()
il.Add("*.example.com")

if !il.Contains("sub.example.com") {
t.Error("expected Contains(sub.example.com) = true for wildcard, got false")
}
if !il.Contains("deep.sub.example.com") {
t.Error("expected Contains(deep.sub.example.com) = true for wildcard, got false")
}
// matchPattern for "*.example.com" also matches "example.com" itself
// because the suffix is "example.com"
if !il.Contains("example.com") {
t.Error("expected Contains(example.com) = true for wildcard base domain, got false")
}
if il.Contains("notexample.com") {
t.Error("expected Contains(notexample.com) = false for unrelated domain, got true")
}
}

// TestInspectionList_DisabledEntry verifies that a disabled entry is not matched.
func TestInspectionList_DisabledEntry(t *testing.T) {
il := NewInspectionList()
il.Add("example.com")
il.Toggle("example.com") // disable it

if il.Contains("example.com") {
t.Error("expected Contains(example.com) = false for disabled entry, got true")
}
}

// TestInspectionList_DisabledWildcard verifies that a disabled wildcard entry is not matched.
func TestInspectionList_DisabledWildcard(t *testing.T) {
il := NewInspectionList()
il.Add("*.example.com")
il.Toggle("*.example.com") // disable it

if il.Contains("sub.example.com") {
t.Error("expected Contains(sub.example.com) = false for disabled wildcard, got true")
}
}

// TestInspectionList_AddReEnables verifies that Add re-enables a disabled entry.
func TestInspectionList_AddReEnables(t *testing.T) {
il := NewInspectionList()
il.Add("example.com")
il.Toggle("example.com") // disable

if il.Contains("example.com") {
t.Fatal("precondition: should be disabled now")
}

il.Add("example.com") // should re-enable
if !il.Contains("example.com") {
t.Error("expected Add to re-enable a disabled entry, but Contains still false")
}
}

// TestInspectionList_Remove verifies that removed entries are no longer matched.
func TestInspectionList_Remove(t *testing.T) {
il := NewInspectionList()
il.Add("example.com")
il.Remove("example.com")

if il.Contains("example.com") {
t.Error("expected Contains(example.com) = false after Remove, got true")
}
}

// TestIsBypassed_DomainInBypassList verifies that bypass list overrides inspection intent.
// This is a conceptual test: IsBypassed is independent of InspectionList, but callers
// should check IsBypassed before Contains to implement bypass-overrides-inspection logic.
func TestIsBypassed_DomainInBypassList(t *testing.T) {
cases := []struct {
domain   string
expected bool
}{
{"chase.com", true},
{"login.chase.com", true},
{"foo.bar.chase.com", true},
{"google.com", true},
{"mail.google.com", true},
{"ocsp.digicert.com", true},
{"update.microsoft.com", true},
{"login.microsoftonline.com", true},
{"ocsp.pki.goog", true},
{"example.com", false},
{"mybank.net", false},
}

for _, tc := range cases {
got := IsBypassed(tc.domain)
if got != tc.expected {
t.Errorf("IsBypassed(%q) = %v, want %v", tc.domain, got, tc.expected)
}
}
}

// TestInspectionList_LoadFrom verifies that LoadFrom and List perform a round-trip.
func TestInspectionList_LoadFrom(t *testing.T) {
input := []InspectionListEntry{
{Pattern: "example.com", Enabled: true},
{Pattern: "*.api.example.com", Enabled: false},
{Pattern: "other.net", Enabled: true},
}

il := NewInspectionList()
il.LoadFrom(input)

got := il.List()
if len(got) != len(input) {
t.Fatalf("LoadFrom+List: got %d entries, want %d", len(got), len(input))
}

// Build a map for easy lookup since List returns sorted order
byPattern := make(map[string]InspectionListEntry, len(got))
for _, e := range got {
byPattern[e.Pattern] = e
}

for _, want := range input {
got, ok := byPattern[want.Pattern]
if !ok {
t.Errorf("LoadFrom+List: missing pattern %q", want.Pattern)
continue
}
if got.Enabled != want.Enabled {
t.Errorf("LoadFrom+List: pattern %q Enabled = %v, want %v", want.Pattern, got.Enabled, want.Enabled)
}
}

// Verify Contains honours Enabled from LoadFrom
if !il.Contains("example.com") {
t.Error("expected Contains(example.com) = true after LoadFrom with Enabled:true")
}
if il.Contains("sub.api.example.com") {
t.Error("expected Contains(sub.api.example.com) = false (entry disabled in LoadFrom)")
}
}

// TestGetBypassList verifies that GetBypassList returns a sorted, non-empty list.
func TestGetBypassList(t *testing.T) {
list := GetBypassList()
if len(list) == 0 {
t.Fatal("GetBypassList() returned empty list")
}
for i := 1; i < len(list); i++ {
if list[i] < list[i-1] {
t.Errorf("GetBypassList() not sorted at index %d: %q < %q", i, list[i], list[i-1])
}
}
}
