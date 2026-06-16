package mitm

import (
	"sort"
	"strings"
	"sync"
)

// InspectionListEntry represents a single domain pattern in the inspection list.
type InspectionListEntry struct {
	Pattern string `json:"pattern"`
	Enabled bool   `json:"enabled"`
}

// InspectionList is a thread-safe in-memory set of domain patterns subject to TLS inspection.
// Patterns can be exact hostnames ("example.com") or wildcards ("*.example.com").
type InspectionList struct {
	exact     map[string]bool
	wildcards []InspectionListEntry
	mu        sync.RWMutex
}

// NewInspectionList returns an empty, ready-to-use InspectionList.
func NewInspectionList() *InspectionList {
	return &InspectionList{
		exact:     make(map[string]bool),
		wildcards: []InspectionListEntry{},
	}
}

// Contains reports whether domain is covered by an enabled entry in the list.
func (il *InspectionList) Contains(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	il.mu.RLock()
	defer il.mu.RUnlock()

	if enabled, ok := il.exact[domain]; ok {
		return enabled
	}
	for _, entry := range il.wildcards {
		if !entry.Enabled {
			continue
		}
		suffix := strings.ToLower(entry.Pattern[2:])
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

// Add adds pattern as an enabled entry (re-enables if already present).
func (il *InspectionList) Add(pattern string) {
	il.mu.Lock()
	defer il.mu.Unlock()

	if strings.HasPrefix(pattern, "*.") {
		for i, e := range il.wildcards {
			if e.Pattern == pattern {
				il.wildcards[i].Enabled = true
				return
			}
		}
		il.wildcards = append(il.wildcards, InspectionListEntry{Pattern: pattern, Enabled: true})
	} else {
		il.exact[pattern] = true
	}
}

// Remove deletes pattern from the list.
func (il *InspectionList) Remove(pattern string) {
	il.mu.Lock()
	defer il.mu.Unlock()

	if strings.HasPrefix(pattern, "*.") {
		filtered := il.wildcards[:0]
		for _, e := range il.wildcards {
			if e.Pattern != pattern {
				filtered = append(filtered, e)
			}
		}
		il.wildcards = filtered
	} else {
		delete(il.exact, pattern)
	}
}

// Toggle flips the Enabled flag for an existing pattern.
func (il *InspectionList) Toggle(pattern string) {
	il.mu.Lock()
	defer il.mu.Unlock()

	if strings.HasPrefix(pattern, "*.") {
		for i, e := range il.wildcards {
			if e.Pattern == pattern {
				il.wildcards[i].Enabled = !e.Enabled
				return
			}
		}
	} else {
		if enabled, ok := il.exact[pattern]; ok {
			il.exact[pattern] = !enabled
		}
	}
}

// List returns all entries in sorted order by pattern.
func (il *InspectionList) List() []InspectionListEntry {
	il.mu.RLock()
	defer il.mu.RUnlock()

	entries := make([]InspectionListEntry, 0, len(il.exact)+len(il.wildcards))
	for pattern, enabled := range il.exact {
		entries = append(entries, InspectionListEntry{Pattern: pattern, Enabled: enabled})
	}
	entries = append(entries, il.wildcards...)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Pattern < entries[j].Pattern
	})
	return entries
}

// LoadFrom replaces the current list state with the provided entries.
func (il *InspectionList) LoadFrom(entries []InspectionListEntry) {
	il.mu.Lock()
	defer il.mu.Unlock()

	il.exact = make(map[string]bool, len(entries))
	il.wildcards = il.wildcards[:0]
	for _, e := range entries {
		if strings.HasPrefix(e.Pattern, "*.") {
			il.wildcards = append(il.wildcards, e)
		} else {
			il.exact[e.Pattern] = e.Enabled
		}
	}
}
