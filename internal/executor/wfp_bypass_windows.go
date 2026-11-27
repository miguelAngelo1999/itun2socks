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
		Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5,
		Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71},
	}
	fwpmConditionIPProtocol = windows.GUID{
		Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a,
		Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7},
	}
	fwpmConditionIPRemotePort = windows.GUID{
		Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a,
		Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b},
	}
)

const (
	fwpActionPermit                = 0x00001002
	fwpActionBlock                 = 0x00001001
	fwpMatchEqual                  = 0
	fwpMatchNotEqual               = 10
	fwpConditionValueTypeUInt8     = 1
	fwpConditionValueTypeUInt16    = 2
	fwpConditionValueTypeBLOB      = 12
	fwpmSessionFlagDynamic         = 0x00000001
	fwpmFilterFlagClearActionRight = 0x00000008
	fwpEmptyValue                  = 0
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
	filterKey          windows.GUID
	displayData        fwpmDisplayData0
	flags              uint32
	providerKey        *windows.GUID
	providerData       fwpByteBlob
	layerKey           windows.GUID
	sublayerKey        windows.GUID
	weight             fwpValue0
	numConditions      uint32
	conditions         *fwpmFilterCondition0
	action             fwpmAction0
	providerContextKey [2]uint64 // union { UINT64 rawContext; GUID providerContextKey; } (align 8, size 16)
	reserved           *windows.GUID
	filterId           uint64
	effectiveWeight    fwpValue0
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

	kernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
)

type WfpBypass struct {
	engine      uintptr
	sublayerKey windows.GUID
	filterKeys  []windows.GUID
}

var (
	wfpBypassMu     sync.Mutex
	globalWfpBypass *WfpBypass
)

func InitWfpBypass() error {
	wfpBypassMu.Lock()
	defer wfpBypassMu.Unlock()
	return initWfpBypassLocked()
}

func initWfpBypassLocked() error {
	if globalWfpBypass != nil {
		return nil
	}
	name, err := windows.UTF16PtrFromString("Lux TUN Bypass")
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString(session name): %w", err)
	}
	desc, err := windows.UTF16PtrFromString("Permits excluded processes to bypass TUN")
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString(session desc): %w", err)
	}
	session := &fwpmSession0{
		displayData: fwpmDisplayData0{name: name, description: desc},
		flags:       fwpmSessionFlagDynamic,
	}
	var engine uintptr
	r, _, _ := procFwpmEngineOpen0.Call(0, 10, 0, uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(&engine))) // 10 = RPC_C_AUTHN_WINNT
	if r != 0 {
		return fmt.Errorf("FwpmEngineOpen0 failed: 0x%08x", r)
	}
	sublayerKey := newGUID()
	sublayerName, err := windows.UTF16PtrFromString("Lux Bypass Sublayer")
	if err != nil {
		procFwpmEngineClose0.Call(engine)
		return fmt.Errorf("UTF16PtrFromString(sublayer name): %w", err)
	}
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
	return AddProcessBypassWithProtocol(exePath, constants.RuleProtocolAny)
}

func AddProcessBypassWithProtocol(exePath string, proto constants.RuleProtocol) error {
	wfpBypassMu.Lock()
	defer wfpBypassMu.Unlock()
	return addProcessBypassWithProtocolLocked(exePath, proto)
}

func addProcessBypassWithProtocolLocked(exePath string, proto constants.RuleProtocol) error {
	var protoLabel string
	var ipProto uintptr
	switch proto {
	case constants.RuleProtocolAny:
		protoLabel = "any"
	case constants.RuleProtocolTCP:
		protoLabel = "tcp"
		ipProto = 6 // IPPROTO_TCP
	case constants.RuleProtocolUDP:
		protoLabel = "udp"
		ipProto = 17 // IPPROTO_UDP
	default:
		return fmt.Errorf("unsupported WFP bypass protocol %q", proto)
	}

	if globalWfpBypass == nil {
		return fmt.Errorf("WFP bypass not initialized")
	}

	appID, err := getWfpAppID(exePath)
	if err != nil {
		return fmt.Errorf("getWfpAppID(%q): %w", exePath, err)
	}
	defer freeWfpAppID(appID)
	filterKey := newGUID()

	var conditions [2]fwpmFilterCondition0
	conditions[0] = fwpmFilterCondition0{
		fieldKey:  fwpmConditionALEAppID,
		matchType: fwpMatchEqual,
		conditionValue: fwpConditionValue0{
			valueType: fwpConditionValueTypeBLOB,
			value:     uintptr(unsafe.Pointer(appID)),
		},
	}
	numConditions := uint32(1)
	if ipProto != 0 {
		conditions[1] = fwpmFilterCondition0{
			fieldKey:  fwpmConditionIPProtocol,
			matchType: fwpMatchEqual,
			conditionValue: fwpConditionValue0{
				valueType: fwpConditionValueTypeUInt8,
				value:     ipProto,
			},
		}
		numConditions = 2
	}

	filterName, err := windows.UTF16PtrFromString(fmt.Sprintf("Lux Bypass (%s): %s", protoLabel, filepath.Base(exePath)))
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString(filter name): %w", err)
	}
	weight := fwpValue0{valueType: fwpEmptyValue}
	filter := &fwpmFilter0{
		filterKey:   filterKey,
		displayData: fwpmDisplayData0{name: filterName},
		// Clear action right (hard/veto permit) so explicit process permits in
		// our 0xFFFF sublayer override ApplyUdpBlock's lower-weight 0x8000 block sublayer.
		flags:         fwpmFilterFlagClearActionRight,
		layerKey:      fwpmLayerALEAuthConnectV4,
		sublayerKey:   globalWfpBypass.sublayerKey,
		weight:        weight,
		numConditions: numConditions,
		conditions:    &conditions[0],
		action:        fwpmAction0{actionType: fwpActionPermit},
	}
	var filterId uint64
	r, _, _ := procFwpmFilterAdd0.Call(globalWfpBypass.engine, uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(&filterId)))
	if r != 0 {
		return fmt.Errorf("FwpmFilterAdd0 failed for %q (%s): 0x%08x", exePath, protoLabel, r)
	}
	globalWfpBypass.filterKeys = append(globalWfpBypass.filterKeys, filterKey)
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "WFP bypass: added %s permit for %v (filterId=%d)"), protoLabel, filepath.Base(exePath), filterId)
	return nil
}

func CloseWfpBypass() {
	wfpBypassMu.Lock()
	defer wfpBypassMu.Unlock()
	closeWfpBypassLocked()
}

func closeWfpBypassLocked() {
	if globalWfpBypass == nil {
		return
	}
	for _, key := range globalWfpBypass.filterKeys {
		k := key
		procFwpmFilterDeleteByKey0.Call(globalWfpBypass.engine, uintptr(unsafe.Pointer(&k)))
	}
	k := globalWfpBypass.sublayerKey
	procFwpmSubLayerDeleteByKey0.Call(globalWfpBypass.engine, uintptr(unsafe.Pointer(&k)))
	procFwpmEngineClose0.Call(globalWfpBypass.engine)
	globalWfpBypass.filterKeys = nil
	globalWfpBypass = nil
	log.Infoln("%s", log.FormatLog(log.ExecutorPrefix, "WFP bypass: closed"))
}

type WfpUdpBlock struct {
	engine      uintptr
	sublayerKey windows.GUID
	filterKey   windows.GUID
}

var (
	udpBlockMu        sync.Mutex
	globalWfpUdpBlock *WfpUdpBlock
)

// ApplyUdpBlock adds a dynamic WFP block sublayer and filter on FWPM_LAYER_ALE_AUTH_CONNECT_V4
// for protocol UDP (17) where remote port != 53 (DNS). The session is dynamic so Windows
// cleans it up automatically if the process exits or stops.
func ApplyUdpBlock() error {
	udpBlockMu.Lock()
	defer udpBlockMu.Unlock()
	if globalWfpUdpBlock != nil {
		return nil
	}

	name, _ := windows.UTF16PtrFromString("Lux Dynamic UDP Block")
	desc, _ := windows.UTF16PtrFromString("Blocks UDP traffic (except DNS) when upstream proxy lacks UDP support")
	session := &fwpmSession0{
		displayData: fwpmDisplayData0{name: name, description: desc},
		flags:       fwpmSessionFlagDynamic,
	}
	var engine uintptr
	r, _, _ := procFwpmEngineOpen0.Call(0, 10, 0, uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(&engine))) // 10 = RPC_C_AUTHN_WINNT
	if r != 0 {
		return fmt.Errorf("FwpmEngineOpen0 failed for UDP block: 0x%08x", r)
	}

	sublayerKey := newGUID()
	sublayerName, _ := windows.UTF16PtrFromString("Lux UDP Block Sublayer")
	sublayer := &fwpmSublayer0{
		sublayerKey: sublayerKey,
		displayData: fwpmDisplayData0{name: sublayerName},
		weight:      0x8000,
	}
	r, _, _ = procFwpmSubLayerAdd0.Call(engine, uintptr(unsafe.Pointer(sublayer)), 0)
	if r != 0 {
		procFwpmEngineClose0.Call(engine)
		return fmt.Errorf("FwpmSubLayerAdd0 failed for UDP block: 0x%08x", r)
	}

	filterKey := newGUID()
	filterName, _ := windows.UTF16PtrFromString("Lux UDP Block: Drop non-DNS UDP")
	conditions := [2]fwpmFilterCondition0{
		{
			fieldKey:  fwpmConditionIPProtocol,
			matchType: fwpMatchEqual,
			conditionValue: fwpConditionValue0{
				valueType: fwpConditionValueTypeUInt8,
				value:     17, // IPPROTO_UDP
			},
		},
		{
			fieldKey:  fwpmConditionIPRemotePort,
			matchType: fwpMatchNotEqual,
			conditionValue: fwpConditionValue0{
				valueType: fwpConditionValueTypeUInt16,
				value:     53, // DNS
			},
		},
	}
	weight := fwpValue0{valueType: fwpEmptyValue}
	filter := &fwpmFilter0{
		filterKey:     filterKey,
		displayData:   fwpmDisplayData0{name: filterName},
		layerKey:      fwpmLayerALEAuthConnectV4,
		sublayerKey:   sublayerKey,
		weight:        weight,
		numConditions: 2,
		conditions:    &conditions[0],
		action:        fwpmAction0{actionType: fwpActionBlock},
	}
	var filterId uint64
	r, _, _ = procFwpmFilterAdd0.Call(engine, uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(&filterId)))
	if r != 0 {
		k := sublayerKey
		procFwpmSubLayerDeleteByKey0.Call(engine, uintptr(unsafe.Pointer(&k)))
		procFwpmEngineClose0.Call(engine)
		return fmt.Errorf("FwpmFilterAdd0 failed for UDP block: 0x%08x", r)
	}

	globalWfpUdpBlock = &WfpUdpBlock{
		engine:      engine,
		sublayerKey: sublayerKey,
		filterKey:   filterKey,
	}
	log.Infoln(log.FormatLog(log.ExecutorPrefix, "WFP UDP block: activated (filterId=%d)"), filterId)
	return nil
}

// CloseUdpBlock explicitly tears down the dynamic WFP UDP block filter, sublayer, and engine.
func CloseUdpBlock() {
	udpBlockMu.Lock()
	defer udpBlockMu.Unlock()
	if globalWfpUdpBlock == nil {
		return
	}

	kFilter := globalWfpUdpBlock.filterKey
	procFwpmFilterDeleteByKey0.Call(globalWfpUdpBlock.engine, uintptr(unsafe.Pointer(&kFilter)))

	kSublayer := globalWfpUdpBlock.sublayerKey
	procFwpmSubLayerDeleteByKey0.Call(globalWfpUdpBlock.engine, uintptr(unsafe.Pointer(&kSublayer)))

	procFwpmEngineClose0.Call(globalWfpUdpBlock.engine)
	globalWfpUdpBlock = nil
	log.Infoln("%s", log.FormatLog(log.ExecutorPrefix, "WFP UDP block: closed"))
}

// IsUdpBlockActive reports whether the dynamic WFP UDP block is currently applied.
func IsUdpBlockActive() bool {
	udpBlockMu.Lock()
	defer udpBlockMu.Unlock()
	return globalWfpUdpBlock != nil
}

func ApplyProcessBypasses() {
	rawConfig, err := configuration.Read()
	if err != nil {
		return
	}
	effective := configuration.EffectiveRulesFrom(rawConfig)
	entries := collectProcessBypasses(rawConfig, effective)

	wfpBypassMu.Lock()
	defer wfpBypassMu.Unlock()

	// Tear down any previous WFP bypass filters so repeated calls are idempotent
	// and deleting all bypass entries removes stale permits.
	closeWfpBypassLocked()
	if len(entries) == 0 {
		return
	}

	// Resolve process names to executable paths and deduplicate on (exePath, protocol),
	// dropping narrower protocol entries when an Any entry resolves to the same binary.
	type resolvedEntry struct {
		exePath  string
		protocol constants.RuleProtocol
	}
	var resolved []resolvedEntry
	hasAnyPath := make(map[string]bool)
	for _, entry := range entries {
		exePath := resolveProcessPath(entry.Process)
		if exePath == "" {
			log.Warnln(log.FormatLog(log.ExecutorPrefix, "WFP bypass: could not resolve path for %q"), entry.Process)
			continue
		}
		if entry.Protocol == constants.RuleProtocolAny {
			hasAnyPath[strings.ToLower(exePath)] = true
		}
		resolved = append(resolved, resolvedEntry{exePath: exePath, protocol: entry.Protocol})
	}
	if len(resolved) == 0 {
		return
	}
	if err := initWfpBypassLocked(); err != nil {
		log.Warnln(log.FormatLog(log.ExecutorPrefix, "WFP bypass init failed: %v"), err)
		return
	}
	type pathProtoKey struct {
		path  string
		proto constants.RuleProtocol
	}
	seen := make(map[pathProtoKey]bool)
	for _, item := range resolved {
		lowerPath := strings.ToLower(item.exePath)
		if item.protocol != constants.RuleProtocolAny && hasAnyPath[lowerPath] {
			continue
		}
		k := pathProtoKey{path: lowerPath, proto: item.protocol}
		if seen[k] {
			continue
		}
		seen[k] = true
		if err := addProcessBypassWithProtocolLocked(item.exePath, item.protocol); err != nil {
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
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", name),
	}
	for _, p := range paths {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}

	// 1. Check WindowsApps packages (e.g. C:\Program Files\WindowsApps\*\<name>)
	if p := findWindowsAppsPath(name); p != "" {
		return p
	}

	// 2. Inspect running processes via Toolhelp32 snapshot & QueryFullProcessImageNameW
	if p := findRunningProcessPath(name); p != "" {
		return p
	}

	return ""
}

func findWindowsAppsPath(name string) string {
	progFiles := os.Getenv("ProgramFiles")
	if progFiles == "" {
		progFiles = `C:\Program Files`
	}
	if matches, err := filepath.Glob(filepath.Join(progFiles, "WindowsApps", "*", name)); err == nil {
		for _, m := range matches {
			if _, err := os.Stat(m); err == nil {
				return m
			}
		}
	}
	if matches, err := filepath.Glob(filepath.Join(progFiles, "WindowsApps", "*", "app", name)); err == nil {
		for _, m := range matches {
			if _, err := os.Stat(m); err == nil {
				return m
			}
		}
	}
	if progW64 := os.Getenv("ProgramW6432"); progW64 != "" && progW64 != progFiles {
		if matches, err := filepath.Glob(filepath.Join(progW64, "WindowsApps", "*", name)); err == nil {
			for _, m := range matches {
				if _, err := os.Stat(m); err == nil {
					return m
				}
			}
		}
	}
	return ""
}

func findRunningProcessPath(targetExe string) string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snap, &entry); err != nil {
		return ""
	}

	for {
		exeName := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(exeName, targetExe) {
			hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
			if err == nil {
				var buf [4096]uint16
				size := uint32(len(buf))
				r, _, _ := procQueryFullProcessImageNameW.Call(
					uintptr(hProc),
					0,
					uintptr(unsafe.Pointer(&buf[0])),
					uintptr(unsafe.Pointer(&size)),
				)
				windows.CloseHandle(hProc)
				if r != 0 && size > 0 {
					p := windows.UTF16ToString(buf[:size])
					if _, err := os.Stat(p); err == nil {
						return p
					}
				}
			}
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return ""
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
