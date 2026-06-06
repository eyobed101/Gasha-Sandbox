package monitor

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// CorrelationEngine maintains an in-memory behavior graph to correlate events.
type CorrelationEngine struct {
	mu           sync.RWMutex
	jobID        string
	processes    map[int]*ProcessNode
	fileWrites   map[int][]string          // PID -> files written
	regWrites    map[int][]string          // PID -> registry keys written
	netConns     map[int][]string          // PID -> dest IP/domain
	apiCalls     map[int][]string          // PID -> API calls made
	injectionMap map[int]map[int]bool      // Source PID -> Target PID -> Injecting actions
	// Task A additions
	dllLoads     map[int][]string          // PID -> DLL image paths loaded (Task A)
	// Task B additions
	dnsQueries   map[int][]string          // PID -> DNS query names (Task B)
	handleAccess map[int][]string          // PID -> object names accessed (Task B)
	// Task C additions
	scriptBlocks map[int][]string          // PID -> PS script block snippets (Task C)
	alerts       chan<- Event
}

type ProcessNode struct {
	PID         int
	PPID        int
	ImagePath   string
	CommandLine string
	SpawnTime   time.Time
	User        string
	Integrity   string
}

func NewCorrelationEngine(jobID string, alerts chan<- Event) *CorrelationEngine {
	return &CorrelationEngine{
		jobID:        jobID,
		processes:    make(map[int]*ProcessNode),
		fileWrites:   make(map[int][]string),
		regWrites:    make(map[int][]string),
		netConns:     make(map[int][]string),
		apiCalls:     make(map[int][]string),
		injectionMap: make(map[int]map[int]bool),
		dllLoads:     make(map[int][]string),
		dnsQueries:   make(map[int][]string),
		handleAccess: make(map[int][]string),
		scriptBlocks: make(map[int][]string),
		alerts:       alerts,
	}
}

// ProcessEvent updates the behavior graph and performs correlation checks.
func (ce *CorrelationEngine) ProcessEvent(ev Event) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	// 1. Update Graph Nodes
	switch ev.EventType {
	case EventProcessCreate:
		pid := ev.PID
		ppid := 0
		image := ""
		cmdline := ""
		user := ""
		integrity := ""

		if val, ok := ev.Data["ppid"].(int); ok {
			ppid = val
		} else if valf, ok := ev.Data["ppid"].(float64); ok {
			ppid = int(valf)
		}
		if val, ok := ev.Data["image_path"].(string); ok {
			image = val
		}
		if val, ok := ev.Data["cmdline"].(string); ok {
			cmdline = val
		}
		if val, ok := ev.Data["user"].(string); ok {
			user = val
		}
		if val, ok := ev.Data["integrity_level"].(string); ok {
			integrity = val
		}

		node := &ProcessNode{
			PID:         pid,
			PPID:        ppid,
			ImagePath:   image,
			CommandLine: cmdline,
			SpawnTime:   ev.Timestamp,
			User:        user,
			Integrity:   integrity,
		}
		ce.processes[pid] = node

		// Run Privilege Escalation Check
		ce.checkPrivilegeEscalation(node, ev.Timestamp)

	case EventFileWrite:
		if path, ok := ev.Data["path"].(string); ok {
			ce.fileWrites[ev.PID] = append(ce.fileWrites[ev.PID], path)
			ce.checkPersistenceToC2(ev.PID, path, "file", ev.Timestamp)
		}

	case EventRegSet:
		if key, ok := ev.Data["key"].(string); ok {
			valName, _ := ev.Data["value_name"].(string)
			fullKey := key
			if valName != "" {
				fullKey = key + "\\" + valName
			}
			ce.regWrites[ev.PID] = append(ce.regWrites[ev.PID], fullKey)
			ce.checkPersistenceToC2(ev.PID, fullKey, "registry", ev.Timestamp)
		}

	case EventNetConnect:
		dest := ""
		if ip, ok := ev.Data["dest_ip"].(string); ok {
			dest = ip
			if port, ok := ev.Data["dest_port"].(int); ok {
				dest = fmt.Sprintf("%s:%d", dest, port)
			} else if portf, ok := ev.Data["dest_port"].(float64); ok {
				dest = fmt.Sprintf("%s:%d", dest, int(portf))
			}
		}
		if domain, ok := ev.Data["domain"].(string); ok && domain != "" {
			dest = fmt.Sprintf("%s (%s)", dest, domain)
		}
		if dest != "" {
			ce.netConns[ev.PID] = append(ce.netConns[ev.PID], dest)
			ce.checkC2Aftermath(ev.PID, dest, ev.Timestamp)
		}

	case EventAPICall:
		apiName, _ := ev.Data["api_name"].(string)
		if apiName != "" {
			ce.apiCalls[ev.PID] = append(ce.apiCalls[ev.PID], apiName)
			ce.checkProcessInjection(ev.PID, apiName, ev.Data, ev.Timestamp)
		}

	// ── Task A: DLL/Image load tracking ──────────────────────────────────────
	case EventImageLoad:
		imageName, _ := ev.Data["image_name"].(string)
		if imageName != "" {
			ce.dllLoads[ev.PID] = append(ce.dllLoads[ev.PID], imageName)
		}
		isReflective, _ := ev.Data["reflective"].(bool)
		if isReflective {
			ce.checkReflectiveInjection(ev.PID, imageName, ev.Timestamp)
		}

	// ── Task A: Thread creation (cross-process) ───────────────────────────────
	case EventThreadCreate:
		// The APICall echo is already emitted in monitor_windows.go; however we
		// also record it here for completeness and future chained correlation.
		targetPID, _ := ev.Data["target_pid"].(int)
		if targetPID == 0 {
			if tf, ok := ev.Data["target_pid"].(float64); ok {
				targetPID = int(tf)
			}
		}
		if targetPID != 0 && targetPID != ev.PID {
			ce.checkProcessInjection(ev.PID, "CreateRemoteThread", ev.Data, ev.Timestamp)
		}

	// ── Task B: DNS query tracking ────────────────────────────────────────────
	case EventNetDNS:
		query, _ := ev.Data["dns_query"].(string)
		if query == "" {
			query, _ = ev.Data["domain"].(string)
		}
		if query != "" {
			ce.dnsQueries[ev.PID] = append(ce.dnsQueries[ev.PID], query)
			// Store domain in netConns so existing checkC2Aftermath() fires
			ce.netConns[ev.PID] = append(ce.netConns[ev.PID], query)
			ce.checkC2Aftermath(ev.PID, query, ev.Timestamp)
		}

	// ── Task B: Handle access tracking ───────────────────────────────────────
	case EventHandleCreate, EventHandleDuplicate:
		objectName, _ := ev.Data["object_name"].(string)
		objectType, _ := ev.Data["object_type"].(string)
		if objectName != "" {
			ce.handleAccess[ev.PID] = append(ce.handleAccess[ev.PID], objectName)
		}
		ce.checkLSASSAccess(ev.PID, objectType, objectName, ev.Timestamp)

	// ── Task C: PowerShell / AMSI script block tracking ───────────────────────
	case EventPowerShell, EventAMSIScan:
		script, _ := ev.Data["script_block"].(string)
		if script != "" {
			// Store a short prefix only (avoid memory bloat from huge blocks)
			prefix := script
			if len(prefix) > 256 {
				prefix = prefix[:256]
			}
			ce.scriptBlocks[ev.PID] = append(ce.scriptBlocks[ev.PID], prefix)
		}
	}
}

// checkPrivilegeEscalation compares parent process context with the child.
func (ce *CorrelationEngine) checkPrivilegeEscalation(child *ProcessNode, t time.Time) {
	parent, exists := ce.processes[child.PPID]
	if !exists {
		return
	}

	// Windows: low/medium integrity spawning high/system integrity
	if parent.Integrity != "" && child.Integrity != "" {
		isParentLow := strings.Contains(strings.ToLower(parent.Integrity), "medium") || strings.Contains(strings.ToLower(parent.Integrity), "low")
		isChildHigh := strings.Contains(strings.ToLower(child.Integrity), "high") || strings.Contains(strings.ToLower(child.Integrity), "system")
		if isParentLow && isChildHigh {
			// Exclude common OS installers/elevations unless they are suspicious
			if !strings.Contains(strings.ToLower(child.ImagePath), "consent.exe") {
				ce.emitAlert(child.PID, "T1068", "Privilege Escalation Detected",
					fmt.Sprintf("Process %s (%d) with integrity '%s' spawned child %s (%d) with elevated integrity '%s'",
						parent.ImagePath, parent.PID, parent.Integrity, child.ImagePath, child.PID, child.Integrity),
					SevHigh, t)
			}
		}
	}

	// Linux: parent runs as non-root (UID != 0), but child runs as root (UID == 0)
	if parent.User != "" && child.User != "" {
		if parent.User != "root" && parent.User != "0" && (child.User == "root" || child.User == "0") {
			// Exclude sudo/su which are normal authorization agents
			baseImage := strings.ToLower(child.ImagePath)
			if !strings.HasSuffix(baseImage, "/sudo") && !strings.HasSuffix(baseImage, "/su") {
				ce.emitAlert(child.PID, "T1068", "Privilege Escalation Detected",
					fmt.Sprintf("Process %s (%d) running as user '%s' spawned child %s (%d) running as elevated user '%s'",
						parent.ImagePath, parent.PID, parent.User, child.ImagePath, child.PID, child.User),
					SevHigh, t)
			}
		}
	}
}

// checkProcessInjection monitors cross-process operations (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, ptrace)
func (ce *CorrelationEngine) checkProcessInjection(sourcePID int, apiName string, args map[string]interface{}, t time.Time) {
	var targetPID int
	var ok bool

	// Retrieve target PID from arguments
	if targetVal, exists := args["target_pid"]; exists {
		if tVal, okInt := targetVal.(int); okInt {
			targetPID = tVal
			ok = true
		} else if tValf, okFloat := targetVal.(float64); okFloat {
			targetPID = int(tValf)
			ok = true
		}
	}

	if !ok || targetPID == 0 || targetPID == sourcePID {
		return
	}

	// Track injection progression
	if ce.injectionMap[sourcePID] == nil {
		ce.injectionMap[sourcePID] = make(map[int]bool)
	}

	lowerAPI := strings.ToLower(apiName)
	if strings.Contains(lowerAPI, "writeprocessmemory") || strings.Contains(lowerAPI, "virtualallocex") || strings.Contains(lowerAPI, "ptrace_poketext") {
		ce.injectionMap[sourcePID][targetPID] = true
	}

	if strings.Contains(lowerAPI, "createremotethread") || strings.Contains(lowerAPI, "ptrace_attach") {
		// If we saw a prior write/allocation to this target PID, raise severity
		if ce.injectionMap[sourcePID][targetPID] {
			ce.emitAlert(sourcePID, "T1055.001", "Process Injection Attack Sequence",
				fmt.Sprintf("Process (%d) performed VirtualAllocEx/WriteProcessMemory followed by a thread execution api (%s) on target process (%d)",
					sourcePID, apiName, targetPID),
				SevCritical, t)
		} else {
			ce.emitAlert(sourcePID, "T1055", "Suspicious Process Access API",
				fmt.Sprintf("Process (%d) called API (%s) targeting remote process (%d)", sourcePID, apiName, targetPID),
				SevHigh, t)
		}
	}
}

// checkPersistenceToC2 checks if writing to a persistent key/file is followed by C2 network connections.
func (ce *CorrelationEngine) checkPersistenceToC2(pid int, objectPath string, objType string, t time.Time) {
	// Look for persistence triggers
	isPersistence := false
	lowerObj := strings.ToLower(objectPath)

	if objType == "registry" {
		// Windows Run keys, Services, Task Scheduler
		if strings.Contains(lowerObj, `\run`) || strings.Contains(lowerObj, `\runonce`) ||
			strings.Contains(lowerObj, `\currentversion\services`) || strings.Contains(lowerObj, `\taskcache\`) {
			isPersistence = true
		}
	} else if objType == "file" {
		// Startup folders, cron files, systemd paths
		if strings.Contains(lowerObj, `\startup\`) || strings.Contains(lowerObj, "/etc/cron") ||
			strings.Contains(lowerObj, "/etc/systemd/system") || strings.Contains(lowerObj, "/etc/rc.local") {
			isPersistence = true
		}
	}

	if !isPersistence {
		return
	}

	// Check if this process already has network connections in history
	if conns, ok := ce.netConns[pid]; ok && len(conns) > 0 {
		ce.emitAlert(pid, "T1547", "Persistence and Outbound Connection",
			fmt.Sprintf("Process (%d) registered persistence via '%s' and has active network connections to %v",
				pid, objectPath, conns),
			SevHigh, t)
	}
}

// checkC2Aftermath checks if an outbound connection correlates with recent persistence activity.
func (ce *CorrelationEngine) checkC2Aftermath(pid int, dest string, t time.Time) {
	// Check if this process previously wrote persistence files or keys
	hasPersistence := false
	var item string

	for _, reg := range ce.regWrites[pid] {
		lowerReg := strings.ToLower(reg)
		if strings.Contains(lowerReg, `\run`) || strings.Contains(lowerReg, `\runonce`) || strings.Contains(lowerReg, `\currentversion\services`) {
			hasPersistence = true
			item = reg
			break
		}
	}

	if !hasPersistence {
		for _, file := range ce.fileWrites[pid] {
			lowerFile := strings.ToLower(file)
			if strings.Contains(lowerFile, `\startup\`) || strings.Contains(lowerFile, "/etc/cron") || strings.Contains(lowerFile, "/etc/systemd/system") {
				hasPersistence = true
				item = file
				break
			}
		}
	}

	if hasPersistence {
		ce.emitAlert(pid, "T1071.001", "C2 Beaconing from Persistent Process",
			fmt.Sprintf("Process (%d) initiated outbound network connection to %s after establishing persistence in '%s'",
				pid, dest, item),
			SevCritical, t)
	}
}

// checkReflectiveInjection alerts when a PE image is mapped into a process
// without a disk-backed file, which is the hallmark of reflective DLL injection.
// Mapped to MITRE T1055.002.
func (ce *CorrelationEngine) checkReflectiveInjection(pid int, imageName string, t time.Time) {
	ce.emitAlert(pid, "T1055.002", "Reflective DLL Injection Detected",
		fmt.Sprintf("Process (%d) loaded an image '%s' with no disk-backed file — reflective injection pattern",
			pid, imageName),
		SevCritical, t)
}

// checkLSASSAccess alerts when a process opens or duplicates a handle to lsass.exe.
// This is a necessary prerequisite for credential dumping tools such as Mimikatz.
// Mapped to MITRE T1003.001.
func (ce *CorrelationEngine) checkLSASSAccess(pid int, objectType, objectName string, t time.Time) {
	if !strings.Contains(strings.ToLower(objectName), "lsass") {
		return
	}
	ce.emitAlert(pid, "T1003.001", "LSASS Handle Access Detected",
		fmt.Sprintf("Process (%d) opened a '%s' handle to '%s' — potential credential dumping precursor",
			pid, objectType, objectName),
		SevCritical, t)
}

func (ce *CorrelationEngine) emitAlert(pid int, ttp string, technique string, details string, severity int, t time.Time) {
	alert := Event{
		JobID:     ce.jobID,
		Timestamp: t,
		EventType: EventEvasion,
		PID:       pid,
		Category:  CatEvasion,
		Severity:  severity,
		Data: map[string]interface{}{
			"technique": technique,
			"details":   details,
			"mitre_ttp": ttp,
		},
	}
	
	// Non-blocking write to alert channel
	select {
	case ce.alerts <- alert:
	default:
	}
}
