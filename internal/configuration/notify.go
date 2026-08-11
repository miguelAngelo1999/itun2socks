package configuration

// NotifyCredentialExpired is set by the API layer to broadcast a
// credential-expired event to connected WebSocket clients. It lives here as a
// function variable rather than a direct import to avoid a cycle between
// internal/configuration and api/routes.
//
// If nil (e.g. in tests), the expiry is still processed but no event is emitted.
var NotifyCredentialExpired func(proxyIds []string)

// NotifyProxySwitch is set by the API layer to broadcast a proxy-switch event
// when failover selects a different proxy. Informational — the UI can show a
// toast rather than requiring user action.
var NotifyProxySwitch func(proxyId, proxyName string)
