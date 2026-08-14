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

var (
	fwpmLayerALEAuthConnectV4 = windows.GUID{
		Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
		Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
	}
	fwpmConditionALEAppID = windows.GUID{
		Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4f37,
		Data4: [8]byte{0x9b, 0x9c, 0x7e, 0x8e, 0x5e, 0x98, 0xdf, 0x68},
	}
)

const (
	fwpActionPermit           = 0x00001000
	fwpMatchEqual             = 0
	fwpConditionValueTypeBLOB = 13
	fwpmSessionFlagDynamic    = 0x00000001
	fwpEmptyValue             = 0
)

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processId            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           uint32
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpmSublayer0 struct {
	sublayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

type fwpByteBlob struct {
	size uint32
	data *byte
}

type fwpmFilter0 struct {
	filterKey       windows.GUID
	displayData     fwpmDisplayData0
	flags           uint32
	providerKey     *windows.GUID
	providerData    fwpByteBlob
	layerKey        windows.GUID
	sublayerKey     windows.GUID
	weight          fwpValue0
	numConditions   uint32
	conditions      *fwpmFilterCondition0
	action          fwpmAction0
	padding1        [8]byte
	reserved        *windows.GUID
	filterId        uint64
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
	padding    [16]byte
}

var (
	fwpuclnt                      = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0           = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0          = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0            = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByKey0    = fwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmSubLayerDeleteByKey0  = fwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmGetAppIdFromFileName0 = fwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = fwpuclnt.NewProc("FwpmFreeMemory0")
)

type WfpBypass struct {
	mu          sync.Mutex
	engine      uintptr
	sublayerKey windows.GUID
	filterKeys  []windows.GUID
}

var globalWfpBypass *WfpBypass

func InitWfpBypass() error {
	if globalWfpBypass != nil {
		return nil
	}
	name, _ := windows.UTF16PtrFromString("Lux TUN Bypass")
	desc, _ := windows.UTF16PtrFromString("Permits excluded processes to bypass TUN")
	session := &fwpmSession0{
		displayData: fwpmDisplayData0{name: name, description: desc},
		flags:       fwpmSessionFlagDynamic,
	}
	var engine uintptr
	r, _, _ := procFwpmEngineOpen0.Call(0, 0, 0, uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(&engine)))
	if r != 0 {
		return fmt.Errorf("FwpmEngineOpen0 failed: 0x%08x", r)
	}
	sublayerKey := newGUID()
	sublayerName, _ := windows.UTF16PtrFromString("Lux Bypass Sublayer")
	sublayer := &fwpmSublayer0{
		sublayerKey: sublayerKey,
		displayData: fwpmDisplayData0{name: sublayerName},
		weight:      0xFFFF,
	}
	r, _, _ = procFwpmSubLayerAdd0.Call(engine, uintptr(unsafe.Pointer(sublayer)), 0)
	if r != 0 {
		procFwpmEngineClose0.Call(engine)
		return fmt.Errorf("FwpmSubLayerAdd0 failed: 0x%08x", r)
	}
	globalWfpBypass = &WfpBypass{engine: engine, sublayerKey: sublayerKey}
	return nil
}

func AddProcessBypass(exePath string) error {
	if globalWfpBypass == nil {
		return fmt.Errorf("WFP bypass not initialized")
	}
	globalWfpBypass.mu.Lock()
	defer globalWfpBypass.mu.Unlock()
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
	weight := fwpValue0{valueType: fwpEmptyValue}
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
	r, _, _ := procFwpmFilterAdd0.Call(globalWfpBypass.engine, uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(&filterId)))
	if r != 0 {
		return fmt.Errorf("FwpmFilterAdd0 failed for %q: 0x%08x", exePath, r)
	}
	globalWfpBypass.filterKeys = append(globalWfpBypass.filterKeys, filterKey)
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "WFP bypass: added permit for %v (filterId=%d)"), filepath.Base(exePath), filterId)
	return nil
}

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

func ApplyProcessBypasses() {
	rawConfig, err := configuration.Read()
	if err != nil {
		return
	}
	var processes []string
	processes = append(processes, rawConfig.Setting.BypassProcesses...)
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

func resolveProcessPath(name string) string {
	if filepath.IsAbs(name) {
		if _, err := os.Stat(name); err == nil {
			return name
		}
		return ""
	}
	if !strings.HasSuffix(strings.ToLower(name), ".exe") {
		name += ".exe"
	}
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
	return name
}

func getWfpAppID(path string) (*fwpByteBlob, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var blob *fwpByteBlob
	r, _, _ := procFwpmGetAppIdFromFileName0.Call(uintptr(unsafe.Pointer(pathPtr)), uintptr(unsafe.Pointer(&blob)))
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

func newGUID() windows.GUID {
	var guid windows.GUID
	coCreateGuid := windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateGuid")
	coCreateGuid.Call(uintptr(unsafe.Pointer(&guid)))
	return guid
}
