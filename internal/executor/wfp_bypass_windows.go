//go:build windows

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/log"
	"golang.org/x/sys/windows"
)

// WFP GUIDs — well-known layer and condition identifiers.
var (
	// FWPM_LAYER_ALE_AUTH_CONNECT_V4 — outbound IPv4 connection authorization.
	// Filters here see the originating process ID and path.
	fwpmLayerALEAuthConnectV4 = windows.GUID{
		Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}

	// FWPM_CONDITION_ALE_APP_ID — matches on the application identity (NT path).
	fwpmConditionALEAppID = windows.GUID{
		Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4f37,
		Data4: [8]byte{0x9b, 0x9c, 0x7e, 0x8e, 0x5e, 0x98, 0xdf, 0x68},
	}
)

// WFP constants
const (
	fwpActionPermit            = 0x00001000
	fwpMatchEqual              = 0
	fwpConditionValueTypeBLOB  = 13
	fwpmSessionFlagDynamic     = 0x00000001
	fwpmFilterFlagNone         = 0
	fwpEmptyValue              = 0
)

// Windows API structs (simplified for our use case)
type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processId            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           uint32 // BOOL
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpmSublayer0 struct {
	sublayerKey windows.GUID
	displayData fwpmDisplayData0
	flags       uint32
	providerKey *windows.GUID
	providerData fwpByteBlob
	weight      uint16
}

type fwpByteBlob struct {
	size uint32
	data *byte
}

type fwpmFilter0 struct {
	filterKey     windows.GUID
	displayData   fwpmDisplayData0
	flags         uint32
	providerKey   *windows.GUID
	providerData  fwpByteBlob
	layerKey      windows.GUID
	sublayerKey   windows.GUID
	weight        fwpValue0
	numConditions uint32
	conditions    *fwpmFilterCondition0
	action        fwpmAction0
	padding1      [8]byte // union context/rawContext/filterType
	reserved      *windows.GUID
	filterId      uint64
	effectiveWeight fwpValue0
}

type fwpValue0 struct {
	valueType uint32
	value     uintptr
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpConditionValue0
}

type fwpConditionValue0 struct {
	valueType uint32
	value     uintptr
}

type fwpmAction0 struct {
	actionType uint32
	padding    [16]byte // union filterType/calloutKey
}

// WFP API
var (
	fwpuclnt                    = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0         = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0        = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0        = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0          = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByKey0  = fwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmSubLayerDeleteByKey0 = fwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmGetAppIdFromFileName0 = fwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0         = fwpuclnt.NewProc("FwpmFreeMemory0")
)

// WfpBypass manages WFP permit filters that exclude specific processes from TUN.
type WfpBypass struct {
	mu          sync.Mutex
	engine      uintptr
	sublayerKey windows.GUID
	filterKeys  []windows.GUID
}

var globalWfpBypass *WfpBypass

// InitWfpBypass creates the WFP engine session and sublayer.
// Uses FWPM_SESSION_FLAG_DYNAMIC so all filters are auto-removed if lux_core crashes.
func InitWfpBypass() error {
	if globalWfpBypass != nil {
		return nil // already initialized
	}

	name, _ := windows.UTF16PtrFromString("Lux TUN Bypass")
	desc, _ := windows.UTF16PtrFromString("Permits excluded processes to bypass TUN")

	session := &fwpmSession0{
		displayData: fwpmDisplayData0{name: name, description: desc},
		flags:       fwpmSessionFlagDynamic,
	}

	var engine uintptr
	r, _, _ := procFwpmEngineOpen0.Call(
		0, // serverName (local)
		0, // authnService (RPC_C_AUTHN_DEFAULT)
		0, // authIdentity
		uintptr(unsafe.Pointer(session)),
		uintptr(unsafe.Pointer(&engine)),
	)
	if r != 0 {
		return fmt.Errorf("FwpmEngineOpen0 failed: 0x%08x", r)
	}

	// Create sublayer
	sublayerKey := newGUID()
	sublayerName, _ := windows.UTF16PtrFromString("Lux Bypass Sublayer")
	sublayer := &fwpmSublayer0{
		sublayerKey: sublayerKey,
		displayData: fwpmDisplayData0{name: sublayerName},
		weight:      0xFFFF, // highest priority
	}
	r, _, _ = procFwpmSubLayerAdd0.Call(engine, uintptr(unsafe.Pointer(sublayer)), 0)
	if r != 0 {
		procFwpmEngineClose0.Call(engine)
		return fmt.Errorf("FwpmSubLayerAdd0 failed: 0x%08x", r)
	}

	globalWfpBypass = &WfpBypass{
		engine:      engine,
		sublayerKey: sublayerKey,
	}
	return nil
}

// AddProcessBypass adds a WFP permit filter for the given exe path.
// Traffic from this process will not be captured by the TUN interface.
func AddProcessBypass(exePath string) error {
	if globalWfpBypass == nil {
		return fmt.Errorf("WFP bypass not initialized")
	}
	globalWfpBypass.mu.Lock()
	defer globalWfpBypass.mu.Unlock()

	// Convert path to WFP app ID (NT format)
	appID, err := getWfpAppID(exePath)
	if err != nil {
		return fmt.Errorf("getWfpAppID(%q): %w", exePath, err)
	}
	defer freeWfpAppID(appID)

	filterKey := newGUID()
	filterName, _ := windows.UTF16PtrFromString(fmt.Sprintf("Lux Bypass: %s", filepath.Base(exePath)))

	condition := fwpmFilterCondition0{
		fieldKey:  fwpmConditionALEAppID,
		matchType: fwpMatchEqual,
		conditionValue: fwpConditionValue0{
			valueType: fwpConditionValueTypeBLOB,
			value:     uintptr(unsafe.Pointer(appID)),
		},
	}

	weight := fwpValue0{valueType: fwpEmptyValue} // auto-weight (sublayer weight applies)

	filter := &fwpmFilter0{
		filterKey:     filterKey,
		displayData:   fwpmDisplayData0{name: filterName},
		layerKey:      fwpmLayerALEAuthConnectV4,
		sublayerKey:   globalWfpBypass.sublayerKey,
		weight:        weight,
		numConditions: 1,
		conditions:    &condition,
		action:        fwpmAction0{actionType: fwpActionPermit},
	}

	var filterId uint64
	r, _, _ := procFwpmFilterAdd0.Call(
		globalWfpBypass.engine,
		uintptr(unsafe.Pointer(filter)),
		0, // security descriptor
		uintptr(unsafe.Pointer(&filterId)),
	)
	if r != 0 {
		return fmt.Errorf("FwpmFilterAdd0 failed for %q: 0x%08x", exePath, r)
	}

	globalWfpBypass.filterKeys = append(globalWfpBypass.filterKeys, filterKey)
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "WFP bypass: added permit for %v (filterId=%d)"),
		filepath.Base(exePath), filterId)
	return nil
}

// CloseWfpBypass removes all bypass filters and closes the WFP engine.
// Safe to call multiple times.
func CloseWfpBypass() {
	if globalWfpBypass == nil {
		return
	}
	globalWfpBypass.mu.Lock()
	defer globalWfpBypass.mu.Unlock()

	for _, key := range globalWfpBypass.filterKeys {
		k := key
		procFwpmFilterDeleteByKey0.Call(globalWfpBypass.engine, uintptr(unsafe.Pointer(&k)))
	}
	k := globalWfpBypass.sublayerKey
	procFwpmSubLayerDeleteByKey0.Call(globalWfpBypass.engine, uintptr(unsafe.Pointer(&k)))
	procFwpmEngineClose0.Call(globalWfpBypass.engine)

	globalWfpBypass.filterKeys = nil
	globalWfpBypass = nil
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "WFP bypass: closed"))
}

// ApplyProcessBypasses reads PROCESS,x,DIRECT rules + explicit bypassProcesses
// from config and creates WFP permit filters for each.
func ApplyProcessBypasses() {
	rawConfig, err := configuration.Read()
	if err != nil {
		return
	}

	var processes []string

	// 1. Explicit bypassProcesses from settings
	processes = append(processes, rawConfig.Setting.BypassProcesses...)

	// 2. Extract PROCESS,x,DIRECT from customized rules
	for _, raw := range rawConfig.Rules {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.SplitN(raw, ",", 4)
		if len(parts) < 3 {
			continue
		}
		ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))
		payload := strings.TrimSpace(parts[1])
		policy := strings.ToUpper(strings.TrimSpace(parts[2]))

		if ruleType != string(constants.RuleProcess) || policy != string(constants.PolicyDirect) {
			continue
		}
		processes = append(processes, payload)
	}

	if len(processes) == 0 {
		return
	}

	if err := InitWfpBypass(); err != nil {
		log.Warnln(log.FormatLog(log.ExecutorPrefix, "WFP bypass init failed: %v"), err)
		return
	}

	for _, proc := range processes {
		proc = strings.TrimSpace(proc)
		if proc == "" {
			continue
		}
		// Resolve to full path if not already absolute
		exePath := resolveProcessPath(proc)
		if exePath == "" {
			log.Warnln(log.FormatLog(log.ExecutorPrefix, "WFP bypass: could not resolve path for %q"), proc)
			continue
		}
		if err := AddProcessBypass(exePath); err != nil {
			log.Warnln(log.FormatLog(log.ExecutorPrefix, "WFP bypass: %v"), err)
		}
	}
}

// resolveProcessPath tries to find the full path of an executable.
func resolveProcessPath(name string) string {
	// If it's already an absolute path, use it directly
	if filepath.IsAbs(name) {
		if _, err := os.Stat(name); err == nil {
			return name
		}
		return ""
	}
	// If it ends with .exe, try where.exe
	if !strings.HasSuffix(strings.ToLower(name), ".exe") {
		name += ".exe"
	}
	// Check common locations
	paths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), name),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), name),
		filepath.Join(os.Getenv("LOCALAPPDATA"), name),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// Fallback: just return the name as-is (WFP may still match)
	return name
}

// getWfpAppID calls FwpmGetAppIdFromFileName0 to get the NT-path blob.
func getWfpAppID(path string) (*fwpByteBlob, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var blob *fwpByteBlob
	r, _, _ := procFwpmGetAppIdFromFileName0.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&blob)),
	)
	if r != 0 {
		return nil, fmt.Errorf("FwpmGetAppIdFromFileName0 failed: 0x%08x", r)
	}
	return blob, nil
}

func freeWfpAppID(blob *fwpByteBlob) {
	if blob != nil {
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&blob)))
	}
}

// newGUID generates a random GUID using crypto/rand via windows package.
func newGUID() windows.GUID {
	var guid windows.GUID
	// Use CoCreateGuid for a proper random GUID
	coCreateGuid := windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateGuid")
	coCreateGuid.Call(uintptr(unsafe.Pointer(&guid)))
	return guid
}

// collectBypassProcesses is a no-op on non-Windows (see bypass_other.go)
// — included here for Windows builds only.
func init() {
	// Register WFP cleanup on process exit
	// (Dynamic session handles this automatically, but belt-and-suspenders)
}
