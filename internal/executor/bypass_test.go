package executor

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultVoipBypassCidrs(t *testing.T) {
	stunIP1 := netip.MustParseAddr("57.144.171.54")
	stunIP2 := netip.MustParseAddr("57.144.67.54")

	var prefixes []netip.Prefix
	for _, cidr := range defaultVoipBypassCidrs {
		prefix, err := netip.ParsePrefix(cidr)
		assert.NoError(t, err, "CIDR should parse: %s", cidr)
		prefixes = append(prefixes, prefix)
	}

	match1 := false
	match2 := false
	for _, p := range prefixes {
		if p.Contains(stunIP1) {
			match1 = true
		}
		if p.Contains(stunIP2) {
			match2 = true
		}
	}

	assert.True(t, match1, "57.144.171.54 must be covered by bypass CIDRs")
	assert.True(t, match2, "57.144.67.54 must be covered by bypass CIDRs")
}
