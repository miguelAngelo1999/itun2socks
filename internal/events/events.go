// Package events provides a broadcast channel for sending structured events
// to all connected Flutter WebSocket clients without creating import cycles.
package events

// broadcastFn is set by api/routes when the hub is initialized.
var broadcastFn func([]byte)

// Register sets the function that broadcasts to WebSocket clients.
// Called once by api/routes during initialization.
func Register(fn func([]byte)) {
	broadcastFn = fn
}

// Broadcast sends msg to all connected WebSocket clients.
// No-op if no broadcast function is registered yet.
func Broadcast(msg []byte) {
	if broadcastFn != nil {
		broadcastFn(msg)
	}
}
