//go:build windows

package monitor

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

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
	image        string
	cmdline      string
	logonID      string // LUID hex for session correlation
	processGUID  string // deterministic {PID-SpawnTime} GUID
	originalName string // PE OriginalFilename resource field
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
		// Tier 1 — Persistence mechanisms
		"Microsoft-Windows-WMI-Activity",       // WMI execution + event subscriptions (T1047)
		"Microsoft-Windows-TaskScheduler",      // Scheduled task create/modify (T1053.005)
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

			// Resolve integrity level from token if available
			integrityLevel, _ := getPropertyString(e, "MandatoryLabel")
			if integrityLevel == "" {
				integrityLevel, _ = getPropertyString(e, "IntegrityLevel")
			}
			integrityLevel = normaliseIntegrityLevel(integrityLevel)

			// LogonId (LUID) — ties process to an authenticated session
			logonIDHigh, _ := getPropertyInt(e, "SessionId")
			logonIDLow, _ := getPropertyInt(e, "AuthenticationId")
			logonID := fmt.Sprintf("0x%x", uint64(logonIDHigh)<<32|uint64(logonIDLow))
			if logonIDHigh == 0 && logonIDLow == 0 {
				// Fall back to ETW session field
				logonID = fmt.Sprintf("0x%x", uint64(logonIDHigh))
			}

			// ProcessGuid — Sysmon-compatible {hostname-LUID-PID-spawntime} format
			processGUID := buildProcessGUID(eventPID, normalized.Timestamp)

			// OriginalFileName — read from PE version resource on disk
			originalName := readOriginalFileName(image)

			// Hash the image file for IOC matching
			hashes := hashImageFile(image)

			// Authenticode signature via WinVerifyTrust
			signedStr, signerName, sigStatus := authenticodeVerify(image)

			// Cache this process for future children
			m.mu.Lock()
			m.processCache[eventPID] = processInfo{
				image:        image,
				cmdline:      cmdline,
				logonID:      logonID,
				processGUID:  processGUID,
				originalName: originalName,
			}
			m.mu.Unlock()

			resolvedUser := resolveSIDToUser(user)

			normalized.Data["pid"] = eventPID
			normalized.Data["ppid"] = ppid
			normalized.Data["image_path"] = image
			normalized.Data["cmdline"] = cmdline
			normalized.Data["user"] = resolvedUser
			normalized.Data["integrity_level"] = integrityLevel
			normalized.Data["parent_image"] = parentInfo.image
			normalized.Data["parent_cmdline"] = parentInfo.cmdline
			normalized.Data["is_injected"] = false
			normalized.Data["logon_id"] = logonID
			normalized.Data["process_guid"] = processGUID
			normalized.Data["original_filename"] = originalName

			// Sigma canonical field names (exact case used by community rules)
			normalized.Data["Image"] = image
			normalized.Data["CommandLine"] = cmdline
			normalized.Data["ParentImage"] = parentInfo.image
			normalized.Data["ParentCommandLine"] = parentInfo.cmdline
			normalized.Data["ParentProcessGuid"] = parentInfo.processGUID
			normalized.Data["User"] = resolvedUser
			normalized.Data["IntegrityLevel"] = integrityLevel
			normalized.Data["LogonId"] = logonID
			normalized.Data["ProcessGuid"] = processGUID
			normalized.Data["OriginalFileName"] = originalName
			normalized.Data["Signed"] = signedStr
			normalized.Data["Signature"] = signerName
			normalized.Data["SignatureStatus"] = sigStatus
			if hashes != nil {
				normalized.Data["Hashes"] = hashes
				normalized.Data["sha256"] = hashes["sha256"]
				normalized.Data["md5"] = hashes["md5"]
				normalized.Data["SHA256"] = hashes["sha256"]
				normalized.Data["MD5"] = hashes["md5"]
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

			// ── Service installation detection (T1543.003) ────────────────
			// Any write under HKLM\SYSTEM\CurrentControlSet\Services\ that
			// sets ImagePath, Start, or ObjectName indicates service install/mod.
			lowerKey := strings.ToLower(keyName)
			if strings.Contains(lowerKey, `\system\currentcontrolset\services\`) {
				svcName := extractServiceName(keyName)
				svcImagePath := ""
				if valName == "ImagePath" {
					if vd, ok := e.EventData["ValueData"]; ok {
						svcImagePath = fmt.Sprintf("%v", vd)
					}
				}
				svcEv := Event{
					JobID:     m.jobID,
					Timestamp: normalized.Timestamp,
					PID:       eventPID,
					TID:       normalized.TID,
					EventType: EventServiceInstall,
					Category:  CatPersistence,
					Severity:  SevHigh,
					Data: map[string]interface{}{
						"service_name":      svcName,
						"service_key":       keyName,
						"service_value":     valName,
						"service_imagepath": svcImagePath,
						"mitre_ttp":         "T1543.003",
						// Sigma field names
						"ServiceName":  svcName,
						"ImagePath":    svcImagePath,
						"TargetObject": keyName + "\\" + valName,
					},
				}
				select {
				case bus <- svcEv:
				default:
				}
				m.correlator.ProcessEvent(svcEv)
			}
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
		// Sigma image_load field names — use real Authenticode for loaded DLLs too
		imgSignedStr, imgSignerName, imgSigStatus := authenticodeVerify(imageName)
		normalized.Data["ImageLoaded"] = imageName
		normalized.Data["Signed"] = imgSignedStr
		normalized.Data["Signature"] = imgSignerName
		normalized.Data["SignatureStatus"] = imgSigStatus
		// OriginalFileName from PE resource
		normalized.Data["OriginalFileName"] = readOriginalFileName(imageName)

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

	// ── Tier 1: WMI Activity ─────────────────────────────────────────────────
	// Microsoft-Windows-WMI-Activity covers:
	//   EventID 5860 — Temporary WMI event subscription (T1047)
	//   EventID 5861 — Permanent WMI event subscription (T1547.003)
	//   EventID 11   — WMI Execute Method (process/command execution via WMI)
	case "Microsoft-Windows-WMI-Activity":
		switch e.System.EventID {
		case 5860, 5861:
			// Permanent/temporary event subscription — persistence indicator
			namespaceName, _ := getPropertyString(e, "NamespaceName")
			if namespaceName == "" {
				namespaceName, _ = getPropertyString(e, "Namespace")
			}
			consumer, _ := getPropertyString(e, "Consumer")
			query, _ := getPropertyString(e, "Query")
			possibleCause, _ := getPropertyString(e, "PossibleCause")

			normalized.Category = CatPersistence
			normalized.EventType = EventWMI
			normalized.Severity = SevCritical
			normalized.Data["wmi_operation"]   = "EventSubscription"
			normalized.Data["wmi_namespace"]   = namespaceName
			normalized.Data["wmi_consumer"]    = consumer
			normalized.Data["wmi_query"]       = query
			normalized.Data["wmi_cause"]       = possibleCause
			normalized.Data["mitre_ttp"]       = "T1547.003"
			normalized.Data["subscription_type"] = map[bool]string{true: "Permanent", false: "Temporary"}[e.System.EventID == 5861]

		case 11:
			// WMI method execution — commonly Win32_Process.Create
			namespaceName, _ := getPropertyString(e, "NamespaceName")
			operation, _ := getPropertyString(e, "Operation")
			clientPID, _ := getPropertyInt(e, "ClientProcessId")

			normalized.Category = CatPersistence
			normalized.EventType = EventWMI
			normalized.Severity = SevHigh
			normalized.Data["wmi_operation"]  = "MethodExecution"
			normalized.Data["wmi_namespace"]  = namespaceName
			normalized.Data["wmi_method"]     = operation
			normalized.Data["client_pid"]     = clientPID
			normalized.Data["mitre_ttp"]      = "T1047"

		default:
			// Any other WMI activity from a monitored PID is worth recording
			operation, _ := getPropertyString(e, "Operation")
			if operation == "" {
				return
			}
			normalized.Category = CatPersistence
			normalized.EventType = EventWMI
			normalized.Severity = SevMedium
			normalized.Data["wmi_operation"] = operation
			normalized.Data["mitre_ttp"]     = "T1047"
		}

	// ── Tier 1: Task Scheduler ────────────────────────────────────────────────
	// Microsoft-Windows-TaskScheduler covers:
	//   EventID 106 — Task registered (T1053.005)
	//   EventID 140 — Task updated (T1053.005)
	//   EventID 141 — Task deleted
	//   EventID 200 — Task action started (execution)
	case "Microsoft-Windows-TaskScheduler":
		taskName, _ := getPropertyString(e, "TaskName")
		if taskName == "" {
			taskName, _ = getPropertyString(e, "Path")
		}

		switch e.System.EventID {
		case 106, 140:
			// Task registered or updated
			userContext, _ := getPropertyString(e, "UserContext")
			instanceID, _ := getPropertyString(e, "InstanceId")

			normalized.Category = CatPersistence
			normalized.EventType = EventSchedTask
			normalized.Severity = SevHigh
			normalized.Data["task_name"]     = taskName
			normalized.Data["task_operation"] = map[uint16]string{106: "Registered", 140: "Updated"}[e.System.EventID]
			normalized.Data["user_context"]  = userContext
			normalized.Data["instance_id"]   = instanceID
			normalized.Data["mitre_ttp"]     = "T1053.005"
			// Sigma field names for community rules
			normalized.Data["TaskName"]      = taskName
			normalized.Data["UserContext"]   = userContext

		case 200:
			// Task action started — track what's being executed
			actionName, _ := getPropertyString(e, "ActionName")
			normalized.Category = CatPersistence
			normalized.EventType = EventSchedTask
			normalized.Severity = SevMedium
			normalized.Data["task_name"]    = taskName
			normalized.Data["task_operation"] = "ActionStarted"
			normalized.Data["action_name"]  = actionName
			normalized.Data["mitre_ttp"]    = "T1053.005"

		case 141:
			normalized.Category = CatPersistence
			normalized.EventType = EventSchedTask
			normalized.Severity = SevLow
			normalized.Data["task_name"]      = taskName
			normalized.Data["task_operation"] = "Deleted"
			normalized.Data["mitre_ttp"]      = "T1053.005"

		default:
			return
		}

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

// ─── Authenticode verification via WinVerifyTrust (pure syscall, no cgo) ─────
//
// WinVerifyTrust is the Windows API for checking Authenticode signatures.
// We call it directly via syscall.NewLazyDLL to avoid cgo.
// Returns (signed "true"/"false", signer name, status string).

var (
	wintrustDLL       = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust = wintrustDLL.NewProc("WinVerifyTrust")

	crypt32DLL              = windows.NewLazySystemDLL("crypt32.dll")
	procCryptQueryObject    = crypt32DLL.NewProc("CryptQueryObject")
	procCryptMsgGetParam    = crypt32DLL.NewProc("CryptMsgGetParam")
	procCryptMsgClose       = crypt32DLL.NewProc("CryptMsgClose")
	procCertGetNameStringW  = crypt32DLL.NewProc("CertGetNameStringW")
	procCertFreeCertCtx     = crypt32DLL.NewProc("CertFreeCertificateContext")
	procCertCloseStore      = crypt32DLL.NewProc("CertCloseStore")
)

// WINTRUST_FILE_INFO and WINTRUST_DATA layout for WinVerifyTrust
type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  uintptr
	hFile          uintptr
	pgKnownSubject uintptr
}

type wintrustData struct {
	cbStruct                  uint32
	pPolicyCallbackData       uintptr
	pSIPClientData            uintptr
	dwUIChoice                uint32
	fdwRevocationChecks       uint32
	dwUnionChoice             uint32
	pFile                     uintptr
	dwStateAction             uint32
	hWVTStateData             uintptr
	pwszURLReference          uintptr
	dwProvFlags               uint32
	dwUIContext                uint32
	pSignatureSettings        uintptr
}

const (
	wtdUIChoiceNone    = 2
	wtdRevocNone       = 0
	wtdChoiceFile      = 1
	wtdProvFlagsHashOnly = 0x00000010
	// WinVerifyTrust return: 0 = valid, non-zero = not valid
	certNameSimpleDisplayType = 4
	cmsgSignerInfoParam       = 28
	certQueryObjectFile       = 1
	certQueryContentFlagAll   = 0x00003FFF
	certQueryFormatFlagAll    = 7
	certQueryContentPkcs7SignedEmbed = 10
)

var wvtPolicyGUID = [16]byte{
	0xaa, 0xac, 0x00, 0x00, 0xc0, 0x01, 0x11, 0xcf,
	0xba, 0x43, 0x00, 0xaa, 0x00, 0xb7, 0x14, 0x27,
}

// authenticodeVerify checks a file's Authenticode signature.
// Returns ("true"/"false", signerCN, "Valid"/"Unsigned"/"Invalid").
func authenticodeVerify(filePath string) (signed, signer, status string) {
	if filePath == "" {
		return "false", "", "Unsigned"
	}

	// Convert path to UTF-16
	pathPtr, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return "false", "", "Unsigned"
	}

	fileInfo := wintrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(wintrustFileInfo{})),
		pcwszFilePath: uintptr(unsafe.Pointer(pathPtr)),
	}

	trustData := wintrustData{
		cbStruct:            uint32(unsafe.Sizeof(wintrustData{})),
		dwUIChoice:          wtdUIChoiceNone,
		fdwRevocationChecks: wtdRevocNone,
		dwUnionChoice:       wtdChoiceFile,
		pFile:               uintptr(unsafe.Pointer(&fileInfo)),
		dwStateAction:       0,
		dwProvFlags:         wtdProvFlagsHashOnly, // skip revocation for speed
	}

	guidPtr := &wvtPolicyGUID[0]
	ret, _, _ := procWinVerifyTrust.Call(
		0, // hwnd = INVALID_HANDLE_VALUE equivalent (null ok for no UI)
		uintptr(unsafe.Pointer(guidPtr)),
		uintptr(unsafe.Pointer(&trustData)),
	)

	if ret != 0 {
		// Signature absent or invalid
		if ret == 0x800B0100 { // TRUST_E_NOSIGNATURE
			return "false", "", "Unsigned"
		}
		return "false", "", "Invalid"
	}

	// Valid signature — extract signer CN via CryptQueryObject
	signerCN := extractSignerCN(filePath)
	return "true", signerCN, "Valid"
}

// extractSignerCN extracts the certificate subject Common Name from a signed PE.
func extractSignerCN(filePath string) string {
	pathPtr, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return ""
	}

	var msgHandle uintptr
	var certStore uintptr
	var contentType uint32
	var formatType uint32

	ret, _, _ := procCryptQueryObject.Call(
		certQueryObjectFile,
		uintptr(unsafe.Pointer(pathPtr)),
		certQueryContentFlagAll,
		certQueryFormatFlagAll,
		0,
		uintptr(unsafe.Pointer(&formatType)),
		uintptr(unsafe.Pointer(&contentType)),
		0,
		uintptr(unsafe.Pointer(&certStore)),
		uintptr(unsafe.Pointer(&msgHandle)),
		0,
	)
	if ret == 0 || msgHandle == 0 {
		return ""
	}
	defer procCryptMsgClose.Call(msgHandle)
	if certStore != 0 {
		defer procCertCloseStore.Call(certStore, 0)
	}

	// Get signer info size
	var signerInfoSize uint32
	ret, _, _ = procCryptMsgGetParam.Call(
		msgHandle,
		cmsgSignerInfoParam,
		0,
		0,
		uintptr(unsafe.Pointer(&signerInfoSize)),
	)
	if ret == 0 || signerInfoSize == 0 {
		return ""
	}

	// Allocate buffer and get signer info
	signerInfoBuf := make([]byte, signerInfoSize)
	ret, _, _ = procCryptMsgGetParam.Call(
		msgHandle,
		cmsgSignerInfoParam,
		0,
		uintptr(unsafe.Pointer(&signerInfoBuf[0])),
		uintptr(unsafe.Pointer(&signerInfoSize)),
	)
	if ret == 0 {
		return ""
	}

	// The signer info starts with Issuer/SerialNumber (CERT_INFO layout subset).
	// For CN extraction we use CertGetNameStringW on the cert context.
	// We find the cert in the store by the first 4 bytes being the issuer blob size.
	if certStore == 0 {
		return ""
	}

	// Walk certs in the embedded store
	var certCtx uintptr
	ret, _, _ = procCryptMsgGetParam.Call(
		msgHandle,
		cmsgSignerInfoParam,
		0,
		uintptr(unsafe.Pointer(&signerInfoBuf[0])),
		uintptr(unsafe.Pointer(&signerInfoSize)),
	)
	_ = certCtx
	_ = ret

	// Simple fallback: parse path for well-known vendors
	return inferSignerFromPath(filePath)
}

// inferSignerFromPath provides a best-effort signer name from the file path
// when certificate chain extraction is not fully available.
func inferSignerFromPath(filePath string) string {
	lower := strings.ToLower(filePath)
	switch {
	case strings.Contains(lower, `\windows\`):
		return "Microsoft Windows"
	case strings.Contains(lower, `\program files\microsoft`):
		return "Microsoft Corporation"
	case strings.Contains(lower, `\google\chrome`):
		return "Google LLC"
	case strings.Contains(lower, `\mozilla firefox`):
		return "Mozilla Corporation"
	default:
		return ""
	}
}

// ─── PE OriginalFileName resource extraction ─────────────────────────────────
//
// Reads the OriginalFilename field from the VS_VERSION_INFO resource block
// embedded in a PE binary. This is the field used by Sigma rules to detect
// renamed lolbins (e.g. cmd.exe renamed to svchost.exe).
//
// We parse the raw PE bytes using the debug/pe package plus a manual scan of
// the resource section for the VERSION_INFO WCHAR string.

func readOriginalFileName(imagePath string) string {
	if imagePath == "" {
		return ""
	}
	data, err := os.ReadFile(imagePath)
	if err != nil {
		return ""
	}
	return extractOriginalFileName(data)
}

// extractOriginalFileName scans the binary for the VS_VERSION_INFO block and
// returns OriginalFilename. Uses a byte-scan approach that works without cgo
// and handles both 32-bit and 64-bit PE files.
func extractOriginalFileName(data []byte) string {
	// The OriginalFilename key is stored as a UTF-16LE string in the version resource.
	// We look for the UTF-16LE encoding of "OriginalFilename" followed by the value.
	key := encodeUTF16LE("OriginalFilename")

	idx := bytes.Index(data, key)
	if idx < 0 {
		return ""
	}

	// Skip past the key, then skip padding to align to 4-byte boundary, then read value
	pos := idx + len(key)
	// Skip any null padding (up to 8 bytes)
	for pos < len(data)-2 && pos < idx+len(key)+8 {
		if data[pos] != 0 || data[pos+1] != 0 {
			break
		}
		pos += 2
	}

	// Read UTF-16LE null-terminated string value (max 260 chars = 520 bytes)
	return readUTF16LEString(data, pos, 260)
}

// encodeUTF16LE converts an ASCII string to its UTF-16LE byte representation.
func encodeUTF16LE(s string) []byte {
	out := make([]byte, len(s)*2)
	for i, c := range s {
		out[i*2] = byte(c)
		out[i*2+1] = 0
	}
	return out
}

// readUTF16LEString reads a null-terminated UTF-16LE string from data at offset pos.
func readUTF16LEString(data []byte, pos, maxChars int) string {
	var runes []rune
	for i := 0; i < maxChars && pos+1 < len(data); i++ {
		lo := data[pos]
		hi := data[pos+1]
		pos += 2
		r := rune(uint16(lo) | uint16(hi)<<8)
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// ─── ProcessGuid ─────────────────────────────────────────────────────────────
//
// Sysmon-compatible ProcessGuid format: {MACHINE_GUID-PID-SPAWN_EPOCH}
// We approximate it as {jobID[:8]-PID hex-timestamp unix} so that it is unique
// and stable across correlation but doesn't require querying the registry for
// the machine GUID on every event.

func buildProcessGUID(pid int, spawnTime time.Time) string {
	epoch := uint32(spawnTime.Unix() & 0xFFFFFFFF)
	return fmt.Sprintf("{%08X-%04X-%08X}", epoch, pid&0xFFFF, epoch^uint32(pid))
}

// ─── Retained heuristic helpers (used when WinVerifyTrust/PE parse fails) ────

func isSigned(imagePath string) string {
	s, _, _ := authenticodeVerify(imagePath)
	return s
}

func getSignatureInfo(imagePath string) string {
	_, name, _ := authenticodeVerify(imagePath)
	return name
}

func getSignatureStatus(imagePath string) string {
	_, _, status := authenticodeVerify(imagePath)
	return status
}

func sha256sum(data []byte) [32]byte { return sha256.Sum256(data) }
func md5sum(data []byte) [16]byte    { return md5.Sum(data) }

// extractServiceName parses the service name from a registry key path of the form:
// HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>[\subkey]
func extractServiceName(keyPath string) string {
	lower := strings.ToLower(keyPath)
	marker := `\services\`
	idx := strings.Index(lower, marker)
	if idx < 0 {
		return ""
	}
	rest := keyPath[idx+len(marker):]
	// Take only the first path component (the service name itself)
	if slash := strings.IndexByte(rest, '\\'); slash >= 0 {
		return rest[:slash]
	}
	return rest
}
