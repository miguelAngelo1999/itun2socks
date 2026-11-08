package executor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectBypassCidrs(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	content := `{
		"setting": {
			"bypassCidrs": ["10.0.0.0/8", "192.168.1.1"]
		},
		"proxy": [
			{"id": "proxy1", "server": "1.2.3.4"}
		],
		"rules": [
			"IP-CIDR,172.16.0.0/12,DIRECT",
			"IP-CIDR,8.8.8.8,PROXY",
			"DOMAIN,google.com,DIRECT"
		]
	}`
	err := os.WriteFile(cfgPath, []byte(content), 0644)
	require.NoError(t, err)

	origPath, _ := configuration.GetConfigFilePath()
	t.Cleanup(func() {
		configuration.SetConfigFilePath(origPath)
	})
	configuration.SetConfigFilePath(cfgPath)

	excludes := collectBypassCidrs()
	var actual []string
	for _, p := range excludes {
		actual = append(actual, p.String())
	}

	assert.Contains(t, actual, "10.0.0.0/8")
	assert.Contains(t, actual, "192.168.1.1/32")
	assert.Contains(t, actual, "1.2.3.4/32")
	assert.Contains(t, actual, "172.16.0.0/12")
	assert.NotContains(t, actual, "8.8.8.8/32")
	assert.NotContains(t, actual, "57.144.0.0/14")
}
