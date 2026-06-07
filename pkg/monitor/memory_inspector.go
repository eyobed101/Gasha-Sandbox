// memory_inspector.go — Real memory forensics for the analysis process.
//
// Implements:
//   • Full VirtualQuery walk of all process pages (Windows)
//   • PE section reconstruction from raw page content
//   • Module diff: PEB LDR loaded-module list vs VirtualQuery results
//   • RWX page detection (T1055)
//   • Shannon entropy scan on executable pages
//   • Auto-dump of suspicious regions → emits EventImageLoad for correlation
//
// The inspector runs as a post-execution step called by the orchestrator after
// the sandboxed process has been allowed to run.  Results feed directly into
// the existing YARA ScanMemory pipeline.

package monitor

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// MemoryRegion describes one contiguous virtual-memory region.
type MemoryRegion struct {
	BaseAddress uintptr
	RegionSize  uintptr
	State       uint32 // MEM_COMMIT | MEM_RESERVE | MEM_FREE
	Protect     uint32 // PAGE_* constants
	Type        uint32 // MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE
	Content     []byte // raw bytes (nil unless dumped)
}

// MemoryFinding is a single suspicious observation from the inspector.
type MemoryFinding struct {
	Address   string
	Size      uintptr
	FindingID string // "RWX", "UnbackedPE", "HiddenModule", "HighEntropy", "PESection"
	Detail    string
	Severity  int    // SevLow … SevCritical
	MITRETTP  string
}

// Windows memory constants
const (
	memCommit  = 0x1000
	memReserve = 0x2000
	memFree    = 0x10000

	memImage   = 0x1000000
	memMapped  = 0x40000
	memPrivate = 0x20000

	pageExecute          = 0x10
	pageExecuteRead      = 0x20
	pageExecuteReadWrite = 0x40
	pageExecuteWriteCopy = 0x80

	processVMRead      = 0x0010
	processQueryInfo   = 0x0400
	processAllAccess   = 0x1F0FFF
)

// MEMORY_BASIC_INFORMATION matches the Win32 struct exactly (64-bit layout).
type memBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	_                 uint32 // alignment
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_                 uint32
}

var (
	modKernel32      = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualQueryEx = modKernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory = modKernel32.NewProc("ReadProcessMemory")
	procOpenProcess  = modKernel32.NewProc("OpenProcess")
)

// InspectProcess performs a full memory forensic scan of the given PID.
// It returns a list of findings and emits events onto bus for correlation.
func InspectProcess(jobID string, pid int, bus chan<- Event) []MemoryFinding {
	var findings []MemoryFinding

	handle, err := openProcessHandle(pid)
	if err != nil {
		return findings
	}
	defer windows.CloseHandle(handle)

	// 1. Walk all virtual memory regions
	regions := walkVirtualMemory(handle)

	// 2. Get the set of legitimately loaded modules from PEB
	knownModules := getLoadedModules(handle)

	for _, region := range regions {
		addr := fmt.Sprintf("0x%X", region.BaseAddress)

		// ── RWX page detection (T1055) ────────────────────────────────────
		if isExecutableWritable(region.Protect) && region.State == memCommit {
			f := MemoryFinding{
				Address:   addr,
				Size:      region.RegionSize,
				FindingID: "RWX",
				Detail:    fmt.Sprintf("PAGE_EXECUTE_READWRITE at %s (size %d bytes) — shellcode staging area", addr, region.RegionSize),
				Severity:  SevHigh,
				MITRETTP:  "T1055",
			}
			findings = append(findings, f)
			emitMemoryEvent(jobID, pid, f, bus)
		}

		// Only dump committed private/mapped regions for deeper analysis
		if region.State != memCommit {
			continue
		}
		if region.RegionSize > 64*1024*1024 { // skip >64MB to avoid OOM
			continue
		}

		// Read region content
		content := readProcessBytes(handle, region.BaseAddress, region.RegionSize)
		if len(content) < 2 {
			continue
		}

		// ── Unbacked PE in private memory (T1055.002) ─────────────────────
		hasMZ := content[0] == 'M' && content[1] == 'Z'
		if hasMZ && region.Type == memPrivate {
			// Verify it's a real PE by checking offset to PE header
			isPE := validatePEHeader(content)
			if isPE {
				// Check if this base address is in the known module list
				if !knownModules[region.BaseAddress] {
					f := MemoryFinding{
						Address:   addr,
						Size:      region.RegionSize,
						FindingID: "UnbackedPE",
						Detail:    fmt.Sprintf("PE image at %s not backed by any loaded module — reflective DLL injection or process hollowing", addr),
						Severity:  SevCritical,
						MITRETTP:  "T1055.002",
					}
					findings = append(findings, f)
					emitMemoryEvent(jobID, pid, f, bus)
				}
			}
		}

		// ── Hidden module (module in VirtualQuery but not in PEB LDR) ──────
		if hasMZ && region.Type == memImage && !knownModules[region.BaseAddress] {
			f := MemoryFinding{
				Address:   addr,
				Size:      region.RegionSize,
				FindingID: "HiddenModule",
				Detail:    fmt.Sprintf("MEM_IMAGE region at %s absent from PEB LDR list — manually mapped or hollowed module", addr),
				Severity:  SevCritical,
				MITRETTP:  "T1055.012",
			}
			findings = append(findings, f)
			emitMemoryEvent(jobID, pid, f, bus)
		}

		// ── High-entropy executable region (T1027 / shellcode) ────────────
		if isExecutable(region.Protect) && len(content) >= 4096 {
			entropy := calculateMemEntropy(content)
			if entropy > 7.2 {
				f := MemoryFinding{
					Address:   addr,
					Size:      region.RegionSize,
					FindingID: "HighEntropy",
					Detail:    fmt.Sprintf("Executable region at %s has Shannon entropy %.2f — packed shellcode or encrypted payload", addr, entropy),
					Severity:  SevHigh,
					MITRETTP:  "T1027",
				}
				findings = append(findings, f)
				emitMemoryEvent(jobID, pid, f, bus)
			}
		}

		// ── PE section reconstruction — detect stomped PE sections ─────────
		if hasMZ && len(content) > 0x40 {
			sections := parsePESections(content)
			for _, sec := range sections {
				if sec.isRWX && sec.virtualSize > 0 {
					f := MemoryFinding{
						Address:   fmt.Sprintf("%s+%s", addr, sec.name),
						Size:      uintptr(sec.virtualSize),
						FindingID: "PESection",
						Detail:    fmt.Sprintf("PE section %s at %s has RWX permissions (VSize=%d) — possible code injection", sec.name, addr, sec.virtualSize),
						Severity:  SevHigh,
						MITRETTP:  "T1055.001",
					}
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

// ─── Windows helpers ──────────────────────────────────────────────────────────

func openProcessHandle(pid int) (windows.Handle, error) {
	h, err := windows.OpenProcess(processVMRead|processQueryInfo, false, uint32(pid))
	if err != nil {
		return 0, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	return h, nil
}

func walkVirtualMemory(handle windows.Handle) []MemoryRegion {
	var regions []MemoryRegion
	var addr uintptr = 0

	for {
		var mbi memBasicInfo
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(handle),
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if ret == 0 {
			break
		}
		regions = append(regions, MemoryRegion{
			BaseAddress: mbi.BaseAddress,
			RegionSize:  mbi.RegionSize,
			State:       mbi.State,
			Protect:     mbi.Protect,
			Type:        mbi.Type,
		})
		addr = mbi.BaseAddress + mbi.RegionSize
		if addr <= mbi.BaseAddress { // overflow guard
			break
		}
	}
	return regions
}

func readProcessBytes(handle windows.Handle, base, size uintptr) []byte {
	if size == 0 || size > 64*1024*1024 {
		return nil
	}
	buf := make([]byte, size)
	var read uintptr
	ret, _, _ := procReadProcessMemory.Call(
		uintptr(handle),
		base,
		uintptr(unsafe.Pointer(&buf[0])),
		size,
		uintptr(unsafe.Pointer(&read)),
	)
	if ret == 0 {
		return nil
	}
	return buf[:read]
}

// getLoadedModules returns the set of base addresses from the PEB LDR list
// by reading the TEB → PEB → PEB_LDR_DATA → InLoadOrderModuleList.
// Falls back to an empty map if the process cannot be read.
func getLoadedModules(handle windows.Handle) map[uintptr]bool {
	known := make(map[uintptr]bool)

	// Use EnumProcessModules via psapi / kernel32 as an alternative to
	// walking PEB manually — simpler and equally accurate.
	psapi := windows.NewLazySystemDLL("psapi.dll")
	enumModules := psapi.NewProc("EnumProcessModules")

	var needed uint32
	// First call: get required buffer size
	enumModules.Call(uintptr(handle), 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return known
	}

	count := needed / uint32(unsafe.Sizeof(uintptr(0)))
	modules := make([]uintptr, count)
	ret, _, _ := enumModules.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if ret == 0 {
		return known
	}

	for _, base := range modules {
		if base != 0 {
			known[base] = true
		}
	}
	return known
}

// ─── PE helpers ───────────────────────────────────────────────────────────────

func validatePEHeader(data []byte) bool {
	if len(data) < 0x40 {
		return false
	}
	// e_lfanew at offset 0x3C
	peOffset := binary.LittleEndian.Uint32(data[0x3C:])
	if uint64(peOffset)+4 > uint64(len(data)) {
		return false
	}
	return data[peOffset] == 'P' && data[peOffset+1] == 'E' &&
		data[peOffset+2] == 0 && data[peOffset+3] == 0
}

type peSection struct {
	name        string
	virtualSize uint32
	isRWX       bool
}

func parsePESections(data []byte) []peSection {
	if !validatePEHeader(data) {
		return nil
	}
	peOff := uint32(binary.LittleEndian.Uint32(data[0x3C:]))

	// IMAGE_FILE_HEADER: Machine at PE+4, NumberOfSections at PE+6
	if int(peOff)+24 > len(data) {
		return nil
	}
	numSections := binary.LittleEndian.Uint16(data[peOff+6:])
	optHeaderSize := binary.LittleEndian.Uint16(data[peOff+20:])

	// Section table starts after optional header
	sectionTableOff := peOff + 24 + uint32(optHeaderSize)
	if int(sectionTableOff)+int(numSections)*40 > len(data) {
		return nil
	}

	var sections []peSection
	for i := 0; i < int(numSections); i++ {
		base := int(sectionTableOff) + i*40
		name := strings.TrimRight(string(data[base:base+8]), "\x00")
		virtualSize := binary.LittleEndian.Uint32(data[base+16:])
		characteristics := binary.LittleEndian.Uint32(data[base+36:])

		// IMAGE_SCN_MEM_EXECUTE=0x20000000, IMAGE_SCN_MEM_WRITE=0x80000000
		isRWX := (characteristics & 0x20000000) != 0 && (characteristics & 0x80000000) != 0

		sections = append(sections, peSection{
			name:        name,
			virtualSize: virtualSize,
			isRWX:       isRWX,
		})
	}
	return sections
}

// ─── Memory event emitter ─────────────────────────────────────────────────────

func emitMemoryEvent(jobID string, pid int, f MemoryFinding, bus chan<- Event) {
	ev := Event{
		JobID:     jobID,
		Timestamp: time.Now(),
		EventType: EventImageLoad,
		PID:       pid,
		Category:  CatMemory,
		Severity:  f.Severity,
		Data: map[string]interface{}{
			"finding_id": f.FindingID,
			"address":    f.Address,
			"size":       f.Size,
			"detail":     f.Detail,
			"mitre_ttp":  f.MITRETTP,
			"reflective": f.FindingID == "UnbackedPE" || f.FindingID == "HiddenModule",
			"image_name": "",
		},
	}
	select {
	case bus <- ev:
	default:
	}
}

// ─── Utility ──────────────────────────────────────────────────────────────────

func isExecutableWritable(protect uint32) bool {
	return protect == pageExecuteReadWrite || protect == pageExecuteWriteCopy
}

func isExecutable(protect uint32) bool {
	return protect == pageExecute || protect == pageExecuteRead ||
		protect == pageExecuteReadWrite || protect == pageExecuteWriteCopy
}

func calculateMemEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var e float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			e -= p * log2f(p)
		}
	}
	return e
}

func log2f(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// ln(x) / ln(2)
	y := (x - 1) / (x + 1)
	y2 := y * y
	sum := 0.0
	term := y
	for i := 0; i < 40; i++ {
		sum += term / float64(2*i+1)
		term *= y2
	}
	return 2 * sum / 0.6931471805599453
}
