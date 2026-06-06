//go:build windows

package monitor

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"golang.org/x/sys/windows"
)

type WindowsMonitor struct {
	jobID         string
	targetPID     int
	cancel        context.CancelFunc
	mu            sync.RWMutex
	monitoredPIDs map[int]bool
	// processCache caches (image_path, cmdline) by PID for parent enrichment
	processCache  map[int]processInfo
	session       *etw.RealTimeSession
	consumer      *etw.Consumer
	correlator    *CorrelationEngine
}

type processInfo struct {
	image   string
	cmdline string
}

func NewMonitor() *WindowsMonitor {
	return &WindowsMonitor{
		monitoredPIDs: make(map[int]bool),
		processCache:  make(map[int]processInfo),
	}
}

func (m *WindowsMonitor) Start(ctx context.Context, jobID string, targetPID int, bus chan<- Event) error {
	m.jobID = jobID
	m.targetPID = targetPID

	// 1. Enforce strict privilege requirement
	if !isAdmin() {
		return fmt.Errorf("administrative privileges required: real-time kernel-level ETW consumption requires elevated context")
	}

	m.mu.Lock()
	m.monitoredPIDs[targetPID] = true
	m.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	// Instantiate the real-time Behavioral Correlation Engine
	m.correlator = NewCorrelationEngine(jobID, bus)

	// 2. Setup a unique name for this analysis trace session
	sessionName := fmt.Sprintf("LEMAS-Session-%d-%d", targetPID, rand.Int31n(100000))
	s := etw.NewRealTimeSession(sessionName)
	m.session = s

	// 3. Register target Kernel providers
	// Original four providers
	providers := []string{
		"Microsoft-Windows-Kernel-Process",
		"Microsoft-Windows-Kernel-File",
		"Microsoft-Windows-Kernel-Registry",
		"Microsoft-Windows-Kernel-Network",
		// Task A — Thread + ImageLoad
		"Microsoft-Windows-Kernel-Thread", // Remote thread injection detection (T1055.001)
		"Microsoft-Windows-Kernel-Image",  // DLL load path + reflective injection (T1055.002)
		// Task B — DNS + Handle
		"Microsoft-Windows-DNS-Client",    // Per-process DNS queries for C2 detection
		"Microsoft-Windows-Kernel-Handle", // LSASS handle opens (T1003.001), mutexes, pipes
		// Task C — AMSI + PowerShell
		"Microsoft-Antimalware-Scan-Interface", // AMSI content scanning (T1059.001)
		"Microsoft-Windows-PowerShell",         // Script block logging EventID 4104 (T1059.001)
	}

	for _, provName := range providers {
		prov, err := etw.ParseProvider(provName)
		if err != nil {
			// Non-fatal: some providers may not be available on all Windows versions.
			// Log as a warning event rather than aborting the whole session.
			bus <- Event{
				JobID:     jobID,
				Timestamp: time.Now(),
				EventType: EventEvasion,
				PID:       targetPID,
				Category:  CatEvasion,
				Severity:  SevLow,
				Data: map[string]interface{}{
					"technique": "ETW Provider Unavailable",
					"details":   fmt.Sprintf("ETW provider %s not found on this system (non-fatal): %v", provName, err),
				},
			}
			continue
		}
		if err := s.EnableProvider(prov); err != nil {
			// Also non-fatal — privilege issues on optional providers should not abort analysis.
			bus <- Event{
				JobID:     jobID,
				Timestamp: time.Now(),
				EventType: EventEvasion,
				PID:       targetPID,
				Category:  CatEvasion,
				Severity:  SevLow,
				Data: map[string]interface{}{
					"technique": "ETW Provider Enable Failed",
					"details":   fmt.Sprintf("Could not enable ETW provider %s: %v", provName, err),
				},
			}
			continue
		}
	}

	// 4. Create the ETW Consumer
	c := etw.NewRealTimeConsumer(ctx)
	m.consumer = c
	c.FromSessions(s)

	// 5. Start consuming and processing events in a background goroutine
	go func() {
		// Feed events to the processor
		go func() {
			for ev := range c.Events {
				m.handleETWEvent(ev, bus)
			}
		}()

		if err := c.Start(); err != nil {
			// If consumer fails to start, report it
			bus <- Event{
				JobID:     jobID,
				Timestamp: time.Now(),
				EventType: EventEvasion,
				PID:       targetPID,
				Category:  CatEvasion,
				Severity:  SevCritical,
				Data: map[string]interface{}{
					"technique": "ETW Consumer Failure",
					"details":   fmt.Sprintf("Real-time consumer stopped with error: %v", err),
				},
			}
		}
	}()

	return nil
}

func (m *WindowsMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel != nil {
		m.cancel()
	}
	if m.consumer != nil {
		m.consumer.Stop()
	}
	if m.session != nil {
		_ = m.session.Stop()
	}
	return nil
}

// InjectSimulatedEvents is removed because simulation is strictly forbidden.
func InjectSimulatedEvents(jobID string, filename string, bus chan<- Event) {
	// No simulation allowed
}

// handleETWEvent parses the raw ETW structure and filters it based on target process hierarchy.
func (m *WindowsMonitor) handleETWEvent(e *etw.Event, bus chan<- Event) {
	eventPID := int(e.System.Execution.ProcessID)
	providerName := e.System.Provider.Name

	m.mu.RLock()
	isMonitored := m.monitoredPIDs[eventPID]
	m.mu.RUnlock()

	// Direct optimization check: if it is Process Create, we must check ParentPID *before* ignoring it
	if providerName == "Microsoft-Windows-Kernel-Process" && e.System.EventID == 1 {
		ppid, _ := getPropertyInt(e, "ParentProcessID")
		m.mu.RLock()
		parentMonitored := m.monitoredPIDs[ppid]
		m.mu.RUnlock()

		if parentMonitored {
			childPID, _ := getPropertyInt(e, "ProcessID")
			m.mu.Lock()
			m.monitoredPIDs[childPID] = true
			m.mu.Unlock()
			
			isMonitored = true
			eventPID = childPID
		}
	}

	if !isMonitored {
		return
	}

	// Translate and normalize
	var normalized Event
	normalized.JobID = m.jobID
	normalized.Timestamp = e.System.TimeCreated.SystemTime
	normalized.PID = eventPID
	normalized.TID = int(e.System.Execution.ThreadID)
	normalized.Data = make(map[string]interface{})

	switch providerName {
	case "Microsoft-Windows-Kernel-Process":
		normalized.Category = CatProcess
		normalized.Severity = SevInfo
		if e.System.EventID == 1 {
			normalized.EventType = EventProcessCreate
			ppid, _ := getPropertyInt(e, "ParentProcessID")
			image, _ := getPropertyString(e, "ImageName")
			if image == "" {
				image, _ = getPropertyString(e, "ImageFileName")
			}
			cmdline, _ := getPropertyString(e, "CommandLine")
			user, _ := getPropertyString(e, "UserSid")

			// Resolve parent image/cmdline from cache
			m.mu.RLock()
			parentInfo := m.processCache[ppid]
			m.mu.RUnlock()

			// Cache this process for future children
			m.mu.Lock()
			m.processCache[eventPID] = processInfo{image: image, cmdline: cmdline}
			m.mu.Unlock()

			// Resolve integrity level from token if available
			integrityLevel, _ := getPropertyString(e, "MandatoryLabel")
			if integrityLevel == "" {
				integrityLevel, _ = getPropertyString(e, "IntegrityLevel")
			}
			integrityLevel = normaliseIntegrityLevel(integrityLevel)

			// Hash the image file for IOC matching
			hashes := hashImageFile(image)

			normalized.Data["pid"] = eventPID
			normalized.Data["ppid"] = ppid
			normalized.Data["image_path"] = image
			normalized.Data["cmdline"] = cmdline
			normalized.Data["user"] = resolveSIDToUser(user)
			normalized.Data["integrity_level"] = integrityLevel
			normalized.Data["parent_image"] = parentInfo.image
			normalized.Data["parent_cmdline"] = parentInfo.cmdline
			normalized.Data["is_injected"] = false
			// Sigma fields (exact names used in community rules)
			normalized.Data["Image"] = image
			normalized.Data["CommandLine"] = cmdline
			normalized.Data["ParentImage"] = parentInfo.image
			normalized.Data["ParentCommandLine"] = parentInfo.cmdline
			normalized.Data["User"] = resolveSIDToUser(user)
			normalized.Data["IntegrityLevel"] = integrityLevel
			if hashes != nil {
				normalized.Data["Hashes"] = hashes
				normalized.Data["sha256"] = hashes["sha256"]
				normalized.Data["md5"] = hashes["md5"]
			}
		} else if e.System.EventID == 2 {
			normalized.EventType = EventProcessExit
			exitCode, _ := getPropertyInt(e, "ExitStatus")
			normalized.Data["pid"] = eventPID
			normalized.Data["exit_code"] = exitCode
			// Clean up cache on exit
			m.mu.Lock()
			delete(m.processCache, eventPID)
			m.mu.Unlock()
		} else {
			return
		}

	case "Microsoft-Windows-Kernel-File":
		normalized.Category = CatFile
		normalized.Severity = SevLow
		fileName, _ := getPropertyString(e, "FileName")
		if fileName == "" {
			return // file event without filename is unparseable
		}

		opcodeName := strings.ToLower(e.System.Opcode.Name)
		if strings.Contains(opcodeName, "write") || e.System.EventID == 20 {
			normalized.EventType = EventFileWrite
			normalized.Data["operation"] = "WRITE"
			normalized.Data["path"] = fileName
			normalized.Data["TargetFilename"] = fileName
		} else if strings.Contains(opcodeName, "delete") || strings.Contains(opcodeName, "cleanup") || e.System.EventID == 15 {
			normalized.EventType = EventFileDelete
			normalized.Data["operation"] = "DELETE"
			normalized.Data["path"] = fileName
			normalized.Data["TargetFilename"] = fileName
		} else if strings.Contains(opcodeName, "rename") || e.System.EventID == 16 {
			normalized.EventType = EventFileWrite
			normalized.Data["operation"] = "RENAME"
			normalized.Data["path"] = fileName
			normalized.Data["TargetFilename"] = fileName
			if newName, ok := getPropertyString(e, "NewFileName"); ok {
				normalized.Data["new_path"] = newName
			}
		} else {
			return // ignore reads, queries, locks to maintain low overhead
		}

	case "Microsoft-Windows-Kernel-Registry":
		normalized.Category = CatRegistry
		normalized.Severity = SevMedium
		keyName, _ := getPropertyString(e, "KeyName")
		if keyName == "" {
			keyName, _ = getPropertyString(e, "RelativeName")
		}
		if keyName == "" {
			return
		}

		opcodeName := strings.ToLower(e.System.Opcode.Name)
		if strings.Contains(opcodeName, "setvalue") || e.System.EventID == 5 {
			normalized.EventType = EventRegSet
			normalized.Data["operation"] = "SET"
			normalized.Data["key"] = keyName
			valName, _ := getPropertyString(e, "ValueName")
			normalized.Data["value_name"] = valName
			normalized.Data["TargetObject"] = keyName + "\\" + valName
			if valData, ok := e.EventData["ValueData"]; ok {
				normalized.Data["value_data"] = fmt.Sprintf("%v", valData)
				normalized.Data["Details"] = fmt.Sprintf("%v", valData)
			}
			normalized.Data["EventType"] = "SetValue"
		} else if strings.Contains(opcodeName, "deletevalue") || e.System.EventID == 7 {
			normalized.EventType = EventRegDelete
			normalized.Data["operation"] = "DELETE"
			normalized.Data["key"] = keyName
			valName, _ := getPropertyString(e, "ValueName")
			normalized.Data["value_name"] = valName
			normalized.Data["TargetObject"] = keyName + "\\" + valName
			normalized.Data["EventType"] = "DeleteValue"
		} else {
			return // ignore opens/reads
		}

	case "Microsoft-Windows-Kernel-Network":
		normalized.Category = CatNetwork
		normalized.Severity = SevHigh
		
		destIP, _ := getPropertyString(e, "daddr")
		if destIP == "" {
			destIP, _ = getPropertyString(e, "DestinationAddress")
		}
		if destIP == "" {
			return
		}
		destPort, _ := getPropertyInt(e, "dport")
		if destPort == 0 {
			destPort, _ = getPropertyInt(e, "DestinationPort")
		}

		normalized.EventType = EventNetConnect
		normalized.Data["protocol"] = "TCP"
		normalized.Data["dest_ip"] = destIP
		normalized.Data["dest_port"] = destPort
		normalized.Data["DestinationIp"] = destIP
		normalized.Data["DestinationPort"] = destPort
		normalized.Data["Initiated"] = true
		// Source address fields
		srcIP, _ := getPropertyString(e, "saddr")
		if srcIP == "" {
			srcIP, _ = getPropertyString(e, "SourceAddress")
		}
		srcPort, _ := getPropertyInt(e, "sport")
		if srcPort == 0 {
			srcPort, _ = getPropertyInt(e, "SourcePort")
		}
		if srcIP != "" {
			normalized.Data["SourceIp"] = srcIP
			normalized.Data["SourcePort"] = srcPort
		}
		if domain, ok := getPropertyString(e, "Domain"); ok {
			normalized.Data["domain"] = domain
			normalized.Data["DestinationHostname"] = domain
		}

	// ── Task A: Thread provider ───────────────────────────────────────────────
	case "Microsoft-Windows-Kernel-Thread":
		// Event ID 1 = Thread start (creation). We are interested in threads whose
		// owning process (ProcessID in payload) differs from the header ProcessID,
		// which indicates a remote thread was injected via CreateRemoteThread.
		if e.System.EventID != 1 {
			return // only thread start events are actionable
		}
		// ProcessID in the payload = the process that OWNS the new thread
		ownerPID, hasOwner := getPropertyInt(e, "ProcessID")
		if !hasOwner {
			ownerPID, hasOwner = getPropertyInt(e, "ProcessId")
		}
		// Header ProcessID = who CALLED the thread creation API
		callerPID := int(e.System.Execution.ProcessID)

		// Reflective self-injection is normal; only flag cross-process creation
		if hasOwner && ownerPID != 0 && ownerPID != callerPID && callerPID != 0 {
			startAddr, _ := getPropertyString(e, "StartAddr")
			if startAddr == "" {
				startAddr, _ = getPropertyString(e, "Win32StartAddr")
			}
			normalized.Category = CatMemory
			normalized.EventType = EventThreadCreate
			normalized.Severity = SevCritical
			normalized.PID = callerPID // source of injection
			normalized.Data["api_name"] = "CreateRemoteThread"
			normalized.Data["target_pid"] = ownerPID
			normalized.Data["start_addr"] = startAddr
			normalized.Data["mitre_ttp"] = "T1055.001"
			// Also emit as APICall so existing checkProcessInjection() in correlator fires
			apiEvent := normalized
			apiEvent.EventType = EventAPICall
			apiEvent.Category = CatAPI
			select {
			case bus <- apiEvent:
			default:
			}
			m.correlator.ProcessEvent(apiEvent)
		} else {
			return // same-process thread start — not suspicious
		}

	// ── Task A: ImageLoad provider ────────────────────────────────────────────
	case "Microsoft-Windows-Kernel-Image":
		// ImageLoad events fire whenever a PE image (EXE or DLL) is mapped into
		// a process. We look for:
		//   • DLLs loaded from suspicious user-writable paths
		//   • Images with no backing file ("\Device\..." is a real path; empty or
		//     device paths with unusual format signal reflective injection)
		imageName, _ := getPropertyString(e, "ImageName")
		if imageName == "" {
			imageName, _ = getPropertyString(e, "FileName")
		}
		if imageName == "" {
			return
		}
		imageBase, _ := getPropertyString(e, "ImageBase")
		imageSize, _ := getPropertyInt(e, "ImageSize")

		lowerImage := strings.ToLower(imageName)
		normalized.Category = CatMemory
		normalized.EventType = EventImageLoad
		normalized.Data["image_name"] = imageName
		normalized.Data["image_base"] = imageBase
		normalized.Data["image_size"] = imageSize

		// Reflective injection: image has no disk-backed path (path is empty,
		// or reports \Device\...\<non-obvious> without a .dll/.exe suffix)
		isReflective := imageName == "" ||
			(!strings.HasSuffix(lowerImage, ".dll") &&
				!strings.HasSuffix(lowerImage, ".exe") &&
				!strings.HasSuffix(lowerImage, ".sys") &&
				strings.HasPrefix(lowerImage, `\device\`))

		// Suspicious user-writable paths
		suspiciousPaths := []string{
			`\temp\`, `\tmp\`, `\appdata\`, `\users\public\`,
			`\programdata\`, `\windows\tasks\`, `\recycle`,
		}
		isSuspiciousPath := false
		for _, p := range suspiciousPaths {
			if strings.Contains(lowerImage, p) {
				isSuspiciousPath = true
				break
			}
		}

		if isReflective {
			normalized.Severity = SevCritical
			normalized.Data["reflective"] = true
			normalized.Data["mitre_ttp"] = "T1055.002"
			normalized.Data["detail"] = "Image mapped with no disk-backed file (reflective DLL injection)"
		} else if isSuspiciousPath {
			normalized.Severity = SevHigh
			normalized.Data["suspicious_path"] = true
			normalized.Data["mitre_ttp"] = "T1055.001"
			normalized.Data["detail"] = fmt.Sprintf("DLL loaded from suspicious writable path: %s", imageName)
		} else {
			return // benign system DLL load — skip
		}
		// Sigma image_load field names
		normalized.Data["ImageLoaded"] = imageName
		normalized.Data["Signed"] = isSigned(imageName)
		normalized.Data["Signature"] = getSignatureInfo(imageName)
		normalized.Data["SignatureStatus"] = getSignatureStatus(imageName)

	// ── Task B: DNS-Client provider ───────────────────────────────────────────
	case "Microsoft-Windows-DNS-Client":
		// EventID 3006 = DNS query initiated; 3008 = query completed.
		// Both carry QueryName. We capture both to ensure coverage.
		if e.System.EventID != 3006 && e.System.EventID != 3008 && e.System.EventID != 3000 {
			return
		}
		queryName, _ := getPropertyString(e, "QueryName")
		if queryName == "" {
			return
		}
		queryType, _ := getPropertyString(e, "QueryType")
		queryStatus, _ := getPropertyString(e, "QueryStatus")
		queryResults, _ := getPropertyString(e, "QueryResults")

		normalized.Category = CatNetwork
		normalized.EventType = EventNetDNS
		normalized.Severity = SevLow
		normalized.Data["dns_query"] = queryName
		normalized.Data["domain"] = queryName
		normalized.Data["query_type"] = queryType
		normalized.Data["query_status"] = queryStatus
		normalized.Data["query_results"] = queryResults
		normalized.Data["protocol"] = "DNS"
		// Sigma dns_query field names
		normalized.Data["QueryName"] = queryName
		normalized.Data["QueryType"] = queryType
		normalized.Data["QueryResults"] = queryResults
		// DNS events fire in the context of the process issuing the query;
		// header ProcessID is the actual querying process.
		normalized.PID = int(e.System.Execution.ProcessID)

	// ── Task B: Kernel-Handle provider ────────────────────────────────────────
	case "Microsoft-Windows-Kernel-Handle":
		// Opcodes/EventIDs for handle operations vary by Windows version;
		// we use opcode name matching as the most portable approach.
		opcodeName := strings.ToLower(e.System.Opcode.Name)
		objectType, _ := getPropertyString(e, "ObjectType")
		objectName, _ := getPropertyString(e, "ObjectName")
		if objectName == "" {
			objectName, _ = getPropertyString(e, "HandleName")
		}

		normalized.Category = CatAPI
		normalized.Severity = SevMedium
		normalized.Data["object_type"] = objectType
		normalized.Data["object_name"] = objectName

		if strings.Contains(opcodeName, "create") || e.System.EventID == 32 || e.System.EventID == 33 {
			normalized.EventType = EventHandleCreate
			// Escalate LSASS opens to critical
			if strings.Contains(strings.ToLower(objectName), "lsass") {
				normalized.Severity = SevCritical
			}
		} else if strings.Contains(opcodeName, "duplicate") || e.System.EventID == 34 {
			targetPID, _ := getPropertyInt(e, "TargetProcessID")
			normalized.EventType = EventHandleDuplicate
			normalized.Data["target_pid"] = targetPID
			if strings.Contains(strings.ToLower(objectName), "lsass") {
				normalized.Severity = SevCritical
			}
		} else {
			return // close/query operations are not actionable
		}

	// ── Task C: AMSI provider ─────────────────────────────────────────────────
	case "Microsoft-Antimalware-Scan-Interface":
		// AMSI fires on any content scan. We capture the raw content, scan it
		// with the inline YARA engine (done in orchestrator via the event data),
		// and emit an EventAMSIScan for the Sigma correlator.
		scanContent, _ := getPropertyString(e, "ScanContent")
		appName, _ := getPropertyString(e, "AppName")
		contentName, _ := getPropertyString(e, "ContentName")
		scanResult, _ := getPropertyString(e, "ScanResult")
		if scanContent == "" && contentName == "" {
			return // empty AMSI event
		}
		normalized.Category = CatScript
		normalized.EventType = EventAMSIScan
		normalized.Severity = SevMedium
		normalized.Data["app_name"] = appName
		normalized.Data["content_name"] = contentName
		normalized.Data["scan_result"] = scanResult
		// Store raw content for inline YARA scanning in the orchestrator pipeline
		if scanContent != "" {
			normalized.Data["script_block"] = scanContent
		}
		normalized.Data["mitre_ttp"] = "T1059.001"

	// ── Task C: PowerShell provider ───────────────────────────────────────────
	case "Microsoft-Windows-PowerShell":
		// Event ID 4104 = Script block logging. This fires for every PowerShell
		// script block executed, capturing the full deobfuscated text that the
		// PowerShell engine processes. Note: 4104 is the ETW event ID, not the
		// classic Windows event log ID.
		// We also accept event ID 4103 (module pipeline logging) and 40961/40962
		// (PowerShell session start) for broader coverage.
		if e.System.EventID != 4104 && e.System.EventID != 4103 {
			return
		}
		scriptBlock, _ := getPropertyString(e, "ScriptBlockText")
		if scriptBlock == "" {
			scriptBlock, _ = getPropertyString(e, "Payload") // 4103 uses Payload field
		}
		if scriptBlock == "" {
			return
		}
		path, _ := getPropertyString(e, "Path")
		scriptBlockID, _ := getPropertyString(e, "ScriptBlockId")

		normalized.Category = CatScript
		normalized.EventType = EventPowerShell
		normalized.Severity = SevMedium
		normalized.Data["script_block"] = scriptBlock
		normalized.Data["script_path"] = path
		normalized.Data["script_block_id"] = scriptBlockID
		normalized.Data["mitre_ttp"] = "T1059.001"
		// Sigma ps_script canonical field names
		normalized.Data["ScriptBlockText"] = scriptBlock
		normalized.Data["Path"] = path

	default:
		return
	}

	// 6. Direct Publish to Bus
	select {
	case bus <- normalized:
	default:
	}

	// 7. Route through Behavioral Correlation Engine
	m.correlator.ProcessEvent(normalized)
}

// Helper functions to safely extract data from map
func getPropertyInt(e *etw.Event, name string) (int, bool) {
	if val, ok := e.EventData[name]; ok {
		return interfaceToInt(val)
	}
	if val, ok := e.UserData[name]; ok {
		return interfaceToInt(val)
	}
	return 0, false
}

func getPropertyString(e *etw.Event, name string) (string, bool) {
	if val, ok := e.EventData[name]; ok {
		if s, ok := val.(string); ok {
			return s, true
		}
	}
	if val, ok := e.UserData[name]; ok {
		if s, ok := val.(string); ok {
			return s, true
		}
	}
	return "", false
}

func interfaceToInt(val interface{}) (int, bool) {
	switch v := val.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case uint32:
		return int(v), true
	case int64:
		return int(v), true
	case uint64:
		return int(v), true
	case float64:
		return int(v), true
	case uint16:
		return int(v), true
	case int16:
		return int(v), true
	case uint8:
		return int(v), true
	case int8:
		return int(v), true
	}
	return 0, false
}

func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

// normaliseIntegrityLevel converts raw SID or label strings to Sigma-expected
// human-readable form: "Low", "Medium", "High", "System".
func normaliseIntegrityLevel(raw string) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "s-1-16-4096") || lower == "low":
		return "Low"
	case strings.Contains(lower, "s-1-16-8192") || lower == "medium":
		return "Medium"
	case strings.Contains(lower, "s-1-16-12288") || lower == "high":
		return "High"
	case strings.Contains(lower, "s-1-16-16384") || lower == "system":
		return "System"
	}
	return raw
}

// resolveSIDToUser maps a SID string to DOMAIN\user form for Sigma User field matching.
func resolveSIDToUser(sidStr string) string {
	if sidStr == "" {
		return ""
	}
	wellKnown := map[string]string{
		"S-1-5-18":     `NT AUTHORITY\SYSTEM`,
		"S-1-5-19":     `NT AUTHORITY\LOCAL SERVICE`,
		"S-1-5-20":     `NT AUTHORITY\NETWORK SERVICE`,
		"S-1-5-32-544": `BUILTIN\Administrators`,
	}
	if name, ok := wellKnown[sidStr]; ok {
		return name
	}
	sid, err := windows.StringToSid(sidStr)
	if err != nil {
		return sidStr
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sidStr
	}
	return domain + `\` + account
}

// hashImageFile computes SHA256+MD5 of the spawned image for hash-based Sigma rules.
// Skips known system paths and returns nil on read errors.
func hashImageFile(imagePath string) map[string]string {
	if imagePath == "" {
		return nil
	}
	lower := strings.ToLower(imagePath)
	// Skip large trusted system binaries for performance
	if strings.HasPrefix(lower, `c:\windows\system32\`) ||
		strings.HasPrefix(lower, `c:\windows\syswow64\`) {
		return nil
	}
	data, err := os.ReadFile(imagePath)
	if err != nil {
		return nil
	}
	sha := fmt.Sprintf("%x", sha256.Sum256(data))
	md := fmt.Sprintf("%x", md5.Sum(data))
	return map[string]string{
		"sha256": sha, "SHA256": sha,
		"md5": md, "MD5": md,
	}
}

// isSigned returns "true"/"false" string for Sigma's Signed field.
// Uses path heuristics as a fast approximation; full Authenticode requires
// WinVerifyTrust which needs cgo or an external library.
func isSigned(imagePath string) string {
	lower := strings.ToLower(imagePath)
	trusted := []string{
		`c:\windows\system32\`, `c:\windows\syswow64\`,
		`c:\windows\winsxs\`, `c:\program files\`, `c:\program files (x86)\`,
	}
	for _, p := range trusted {
		if strings.HasPrefix(lower, p) {
			return "true"
		}
	}
	return "false"
}

func getSignatureInfo(imagePath string) string {
	lower := strings.ToLower(imagePath)
	if strings.Contains(lower, `c:\windows\`) {
		return "Microsoft Windows"
	}
	if strings.Contains(lower, `c:\program files\microsoft`) {
		return "Microsoft Corporation"
	}
	return ""
}

func getSignatureStatus(imagePath string) string {
	if isSigned(imagePath) == "true" {
		return "Valid"
	}
	return "Unsigned"
}

func sha256sum(data []byte) [32]byte { return sha256.Sum256(data) }
func md5sum(data []byte) [16]byte    { return md5.Sum(data) }
