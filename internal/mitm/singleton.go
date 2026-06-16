package mitm

import "sync"

var (
	globalCA            *CA
	globalCAMu          sync.RWMutex
	globalInterceptor   InterceptorWithList
	globalInterceptorMu sync.RWMutex
)

// InterceptorWithList is the minimal interface the route handler needs from the interceptor.
type InterceptorWithList interface {
	InspectionList() *InspectionList
}

// GetGlobalCA returns the package-level CA singleton (may be nil if not initialised).
func GetGlobalCA() *CA {
	globalCAMu.RLock()
	defer globalCAMu.RUnlock()
	return globalCA
}

// SetGlobalCA stores the package-level CA singleton.
func SetGlobalCA(ca *CA) {
	globalCAMu.Lock()
	defer globalCAMu.Unlock()
	globalCA = ca
}

// GetOrInitCA returns the global CA, initialising it from configDir if not yet set.
func GetOrInitCA(configDir string) (*CA, error) {
	globalCAMu.RLock()
	if globalCA != nil {
		globalCAMu.RUnlock()
		return globalCA, nil
	}
	globalCAMu.RUnlock()

	globalCAMu.Lock()
	defer globalCAMu.Unlock()
	if globalCA != nil {
		return globalCA, nil
	}
	ca, err := Init(configDir)
	if err != nil {
		return nil, err
	}
	globalCA = ca
	return ca, nil
}

// GetGlobalInterceptor returns the package-level interceptor singleton (may be nil).
func GetGlobalInterceptor() InterceptorWithList {
	globalInterceptorMu.RLock()
	defer globalInterceptorMu.RUnlock()
	return globalInterceptor
}

// SetGlobalInterceptor stores the package-level interceptor singleton.
func SetGlobalInterceptor(i InterceptorWithList) {
	globalInterceptorMu.Lock()
	defer globalInterceptorMu.Unlock()
	globalInterceptor = i
}
