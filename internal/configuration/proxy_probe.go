package configuration

import "fmt"

// GetProxyProbeTarget returns "host:port" of the currently selected upstream proxy.
// Used by the load balancer as its health-check target so it works on corporate
// networks where direct TCP to external IPs (e.g. 8.8.8.8) is blocked.
func GetProxyProbeTarget() string {
	selectedId, err := GetSelectedId("proxy")
	if err != nil || selectedId == "" || selectedId == "DIRECT" {
		return ""
	}
	rawProxy, err := GetProxy(selectedId)
	if err != nil {
		return ""
	}
	server, _ := rawProxy["server"].(string)
	port := 0
	switch v := rawProxy["port"].(type) {
	case float64:
		port = int(v)
	case int:
		port = v
	}
	if server == "" || port == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", server, port)
}
