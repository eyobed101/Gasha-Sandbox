package monitor

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── Time-window constants ────────────────────────────────────────────────────
//
// Injection sequences must complete within primaryWindow.
// Beyond that window, individual API calls are still flagged but not as a
// confirmed multi-step chain.  maxWindow is the hard expiry for all state.

const (
	injectionPrimaryWindow = 10 * time.Second // VirtualAllocEx → CreateRemoteThread
	injectionMaxWindow     = 30 * time.Second // absolute TTL for injection state
)

// ─── processKey ───────────────────────────────────────────────────────────────

type processKey struct {
	PID       int
	SpawnTime int64 // Unix nanoseconds — guards against PID reuse
}

// ─── injectionState tracks the multi-step injection sequence per source PID ──

type injectionState struct {
	targetPID  int
	hasAlloc   bool      // VirtualAllocEx / WriteProcessMemory seen
	firstSeen  time.Time // time of first relevant API call
	lastSeen   time.Time // time of most recent relevant API call
}

// expired returns true when the state is too old to be part of an injection chain.
func (s *injectionState) expired(now time.Time) bool {
	return now.Sub(s.firstSeen) > injectionMaxWindow
}

// withinPrimaryWindow returns true if the triggering API arrived within the
// tight primary window relative to the first preparation call.
func (s *injectionState) withinPrimaryWindow(now time.Time) bool {
	return now.Sub(s.firstSeen) <= injectionPrimaryWindow
}

// ─── CorrelationEngine ────────────────────────────────────────────────────────

type CorrelationEngine struct {
	mu sync.RWMutex

	jobID string

	// Process graph
	processes map[processKey]*ProcessNode
	pidToKey  map[int]processKey

	// Behavioral state maps (keyed by PID)
	fileWrites   map[int][]string
	regWrites    map[int][]string
	netConns     map[int][]string
	apiCalls     map[int][]string
	dllLoads     map[int][]string
	dnsQueries   map[int][]string
	handleAccess map[int][]string
	scriptBlocks map[int][]string

	// Time-windowed injection state: sourcePID → map[targetPID]*injectionState
	// Replaces the old unbounded bool map that fired even 90s after prep calls.
	injectionState map[int]map[int]*injectionState

	// Persistence detection state
	wmiSubscriptions  map[int][]string // PID → subscription names
	scheduledTasks    map[int][]string // PID → task names registered
	servicesInstalled map[int][]string // PID → service names installed

	alerts chan<- Event
}

type ProcessNode struct {
	PID          int
	PPID         int
	ImagePath    string
	CommandLine  string
	OriginalName string
	SpawnTime    time.Time
	User         string
	Integrity    string
	ProcessGUID  string
	LogonID      string
}

func NewCorrelationEngine(jobID string, alerts chan<- Event) *CorrelationEngine {
	return &CorrelationEngine{
		jobID:             jobID,
		processes:         make(map[processKey]*ProcessNode),
		pidToKey:          make(map[int]processKey),
		fileWrites:        make(map[int][]string),
		regWrites:         make(map[int][]string),
		netConns:          make(map[int][]string),
		apiCalls:          make(map[int][]string),
		injectionState:    make(map[int]map[int]*injectionState),
		dllLoads:          make(map[int][]string),
		dnsQueries:        make(map[int][]string),
		handleAccess:      make(map[int][]string),
		scriptBlocks:      make(map[int][]string),
		wmiSubscriptions:  make(map[int][]string),
		scheduledTasks:    make(map[int][]string),
		servicesInstalled: make(map[int][]string),
		alerts:            alerts,
	}
}

// ProcessEvent updates the behavior graph and fires correlation checks.
func (ce *CorrelationEngine) ProcessEvent(ev Event) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	switch ev.EventType {

	case EventProcessCreate:
		node := ce.buildProcessNode(ev)
		key := processKey{PID: ev.PID, SpawnTime: ev.Timestamp.UnixNano()}
		ce.processes[key] = node
		ce.pidToKey[ev.PID] = key
		ce.checkPrivilegeEscalation(node, ev.Timestamp)
		ce.checkLolbinRename(node, ev.Timestamp)
		// Detect schtasks.exe / sc.exe spawned by the monitored process
		ce.checkPersistenceToolSpawn(node, ev.Timestamp)

	case EventProcessExit:
		if key, ok := ce.pidToKey[ev.PID]; ok {
			delete(ce.processes, key)
			delete(ce.pidToKey, ev.PID)
		}
		delete(ce.fileWrites, ev.PID)
		delete(ce.regWrites, ev.PID)
		delete(ce.netConns, ev.PID)
		delete(ce.apiCalls, ev.PID)
		delete(ce.injectionState, ev.PID)
		delete(ce.dllLoads, ev.PID)
		delete(ce.dnsQueries, ev.PID)
		delete(ce.handleAccess, ev.PID)
		delete(ce.scriptBlocks, ev.PID)
		delete(ce.wmiSubscriptions, ev.PID)
		delete(ce.scheduledTasks, ev.PID)
		delete(ce.servicesInstalled, ev.PID)

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
		dest := buildDestString(ev)
		if dest != "" {
			ce.netConns[ev.PID] = append(ce.netConns[ev.PID], dest)
			ce.checkC2Aftermath(ev.PID, dest, ev.Timestamp)
		}

	case EventAPICall:
		apiName, _ := ev.Data["api_name"].(string)
		if apiName != "" {
			ce.apiCalls[ev.PID] = append(ce.apiCalls[ev.PID], apiName)
			ce.checkProcessInjectionWindowed(ev.PID, apiName, ev.Data, ev.Timestamp)
		}

	case EventImageLoad:
		imageName, _ := ev.Data["image_name"].(string)
		if imageName != "" {
			ce.dllLoads[ev.PID] = append(ce.dllLoads[ev.PID], imageName)
		}
		if reflective, _ := ev.Data["reflective"].(bool); reflective {
			ce.checkReflectiveInjection(ev.PID, imageName, ev.Timestamp)
		}

	case EventThreadCreate:
		targetPID := extractTargetPID(ev.Data)
		if targetPID != 0 && targetPID != ev.PID {
			ce.checkProcessInjectionWindowed(ev.PID, "CreateRemoteThread", ev.Data, ev.Timestamp)
		}

	case EventNetDNS:
		query, _ := ev.Data["dns_query"].(string)
		if query == "" {
			query, _ = ev.Data["domain"].(string)
		}
		if query != "" {
			ce.dnsQueries[ev.PID] = append(ce.dnsQueries[ev.PID], query)
			ce.netConns[ev.PID] = append(ce.netConns[ev.PID], query)
			ce.checkC2Aftermath(ev.PID, query, ev.Timestamp)
		}

	case EventHandleCreate, EventHandleDuplicate:
		objectName, _ := ev.Data["object_name"].(string)
		objectType, _ := ev.Data["object_type"].(string)
		if objectName != "" {
			ce.handleAccess[ev.PID] = append(ce.handleAccess[ev.PID], objectName)
		}
		ce.checkLSASSAccess(ev.PID, objectType, objectName, ev.Timestamp)

	case EventPowerShell, EventAMSIScan:
		script, _ := ev.Data["script_block"].(string)
		if script != "" {
			prefix := script
			if len(prefix) > 256 {
				prefix = prefix[:256]
			}
			ce.scriptBlocks[ev.PID] = append(ce.scriptBlocks[ev.PID], prefix)
		}

	// ── Persistence mechanism events ─────────────────────────────────────────

	case EventWMI:
		op, _ := ev.Data["wmi_operation"].(string)
		consumer, _ := ev.Data["wmi_consumer"].(string)
		query, _ := ev.Data["wmi_query"].(string)
		mitre, _ := ev.Data["mitre_ttp"].(string)

		if op == "EventSubscription" {
			name := consumer
			if name == "" {
				name = query
			}
			ce.wmiSubscriptions[ev.PID] = append(ce.wmiSubscriptions[ev.PID], name)
			// Subscription + network = C2 persistence setup
			if conns := ce.netConns[ev.PID]; len(conns) > 0 {
				ce.emitAlert(ev.PID, mitre, "WMI Persistence with C2 Connectivity",
					fmt.Sprintf("PID(%d) created WMI subscription '%s' and has active connections %v",
						ev.PID, name, conns),
					SevCritical, ev.Timestamp)
			} else {
				ce.emitAlert(ev.PID, mitre, "WMI Event Subscription Created",
					fmt.Sprintf("PID(%d) created WMI subscription: consumer=%s query=%s",
						ev.PID, consumer, query),
					SevHigh, ev.Timestamp)
			}
		} else if op == "MethodExecution" {
			method, _ := ev.Data["wmi_method"].(string)
			ce.emitAlert(ev.PID, "T1047", "WMI Method Execution",
				fmt.Sprintf("PID(%d) executed WMI method: %s", ev.PID, method),
				SevHigh, ev.Timestamp)
		}

	case EventSchedTask:
		op, _ := ev.Data["task_operation"].(string)
		taskName, _ := ev.Data["task_name"].(string)

		if op == "Registered" || op == "Updated" {
			ce.scheduledTasks[ev.PID] = append(ce.scheduledTasks[ev.PID], taskName)
			sev := SevHigh
			detail := fmt.Sprintf("PID(%d) registered scheduled task '%s'", ev.PID, taskName)
			// Schtask + network = likely staging for persistent C2 execution
			if conns := ce.netConns[ev.PID]; len(conns) > 0 {
				sev = SevCritical
				detail = fmt.Sprintf("PID(%d) registered scheduled task '%s' and has C2 connections %v",
					ev.PID, taskName, conns)
			}
			ce.emitAlert(ev.PID, "T1053.005", "Scheduled Task Persistence", detail, sev, ev.Timestamp)
		}

	case EventServiceInstall:
		svcName, _ := ev.Data["service_name"].(string)
		imgPath, _ := ev.Data["service_imagepath"].(string)

		if svcName != "" {
			ce.servicesInstalled[ev.PID] = append(ce.servicesInstalled[ev.PID], svcName)
			sev := SevHigh
			detail := fmt.Sprintf("PID(%d) installed service '%s' (ImagePath: %s)", ev.PID, svcName, imgPath)
			// Service install + network = T1543.003 + T1071 combination
			if conns := ce.netConns[ev.PID]; len(conns) > 0 {
				sev = SevCritical
				detail = fmt.Sprintf("PID(%d) installed service '%s' and has C2 connections %v",
					ev.PID, svcName, conns)
			}
			ce.emitAlert(ev.PID, "T1543.003", "Malicious Service Installation", detail, sev, ev.Timestamp)
		}
	}
}

// ─── Process injection — time-windowed ───────────────────────────────────────
//
// Old approach: a simple bool map fired whenever CreateRemoteThread appeared
// after any prior VirtualAllocEx in the same session — even 90 seconds later.
//
// New approach: each (sourcePID, targetPID) pair has a timestamped state entry.
// The multi-step injection alert only fires if CreateRemoteThread arrives within
// injectionPrimaryWindow (10s) of the first preparation call.
// Beyond that, single suspicious API calls still get low-confidence alerts.
// All state expires after injectionMaxWindow (30s).

func (ce *CorrelationEngine) checkProcessInjectionWindowed(
	sourcePID int, apiName string, args map[string]interface{}, now time.Time,
) {
	targetPID := extractTargetPID(args)
	if targetPID == 0 || targetPID == sourcePID {
		return
	}

	lower := strings.ToLower(apiName)

	// Ensure per-source map exists
	if ce.injectionState[sourcePID] == nil {
		ce.injectionState[sourcePID] = make(map[int]*injectionState)
	}

	// Expire stale state for this target
	if st, ok := ce.injectionState[sourcePID][targetPID]; ok && st.expired(now) {
		delete(ce.injectionState[sourcePID], targetPID)
	}

	isPrep := strings.Contains(lower, "writeprocessmemory") ||
		strings.Contains(lower, "virtualallocex") ||
		strings.Contains(lower, "ptrace_poketext")

	isExec := strings.Contains(lower, "createremotethread") ||
		strings.Contains(lower, "ntcreatethread") ||
		strings.Contains(lower, "ptrace_attach") ||
		strings.Contains(lower, "ptrace_seize")

	if isPrep {
		if _, exists := ce.injectionState[sourcePID][targetPID]; !exists {
			ce.injectionState[sourcePID][targetPID] = &injectionState{
				targetPID: targetPID,
				firstSeen: now,
				lastSeen:  now,
			}
		}
		st := ce.injectionState[sourcePID][targetPID]
		st.hasAlloc = true
		st.lastSeen = now
		return
	}

	if isExec {
		st, hasPrior := ce.injectionState[sourcePID][targetPID]

		if hasPrior && st.hasAlloc && st.withinPrimaryWindow(now) {
			// Full confirmed injection chain within the tight window
			ce.emitAlert(sourcePID, "T1055.001", "Process Injection — Confirmed Chain",
				fmt.Sprintf("PID(%d) performed memory prep then %s on PID(%d) within %s window",
					sourcePID, apiName, targetPID,
					now.Sub(st.firstSeen).Round(time.Millisecond)),
				SevCritical, now)
		} else if hasPrior && st.hasAlloc {
			// Window expired — still suspicious but lower confidence
			elapsed := now.Sub(st.firstSeen).Round(time.Second)
			ce.emitAlert(sourcePID, "T1055", "Suspicious Cross-Process API (late)",
				fmt.Sprintf("PID(%d) called %s on PID(%d) — prep was %s ago (outside %s primary window)",
					sourcePID, apiName, targetPID, elapsed, injectionPrimaryWindow),
				SevHigh, now)
		} else {
			// No prior prep — standalone thread creation in foreign process
			ce.emitAlert(sourcePID, "T1055", "Remote Thread Without Prior Allocation",
				fmt.Sprintf("PID(%d) called %s on PID(%d) with no prior memory write observed",
					sourcePID, apiName, targetPID),
				SevHigh, now)
		}
		// Clear state after exec
		delete(ce.injectionState[sourcePID], targetPID)
	}
}

// ─── Node builder ─────────────────────────────────────────────────────────────

func (ce *CorrelationEngine) buildProcessNode(ev Event) *ProcessNode {
	node := &ProcessNode{PID: ev.PID, SpawnTime: ev.Timestamp}
	if v, ok := ev.Data["ppid"].(int); ok {
		node.PPID = v
	} else if v, ok := ev.Data["ppid"].(float64); ok {
		node.PPID = int(v)
	}
	if v, ok := ev.Data["image_path"].(string); ok {
		node.ImagePath = v
	}
	if v, ok := ev.Data["cmdline"].(string); ok {
		node.CommandLine = v
	}
	if v, ok := ev.Data["user"].(string); ok {
		node.User = v
	}
	if v, ok := ev.Data["integrity_level"].(string); ok {
		node.Integrity = v
	}
	if v, ok := ev.Data["process_guid"].(string); ok {
		node.ProcessGUID = v
	}
	if v, ok := ev.Data["logon_id"].(string); ok {
		node.LogonID = v
	}
	if v, ok := ev.Data["original_filename"].(string); ok {
		node.OriginalName = v
	} else if v, ok := ev.Data["OriginalFileName"].(string); ok {
		node.OriginalName = v
	}
	return node
}

// ─── Correlation checks ───────────────────────────────────────────────────────

func (ce *CorrelationEngine) checkPrivilegeEscalation(child *ProcessNode, t time.Time) {
	parentKey, ok := ce.pidToKey[child.PPID]
	if !ok {
		return
	}
	parent, ok := ce.processes[parentKey]
	if !ok {
		return
	}
	if parent.Integrity != "" && child.Integrity != "" {
		pLow  := strings.Contains(strings.ToLower(parent.Integrity), "medium") ||
			strings.Contains(strings.ToLower(parent.Integrity), "low")
		cHigh := strings.Contains(strings.ToLower(child.Integrity), "high") ||
			strings.Contains(strings.ToLower(child.Integrity), "system")
		if pLow && cHigh &&
			!strings.Contains(strings.ToLower(child.ImagePath), "consent.exe") {
			ce.emitAlert(child.PID, "T1068", "Privilege Escalation Detected",
				fmt.Sprintf("%s(%d)[%s] → %s(%d)[%s]",
					parent.ImagePath, parent.PID, parent.Integrity,
					child.ImagePath, child.PID, child.Integrity),
				SevHigh, t)
		}
	}
	if parent.User != "" && child.User != "" {
		pNonRoot := parent.User != "root" && parent.User != "0"
		cRoot    := child.User == "root" || child.User == "0"
		img := strings.ToLower(child.ImagePath)
		if pNonRoot && cRoot &&
			!strings.HasSuffix(img, "/sudo") && !strings.HasSuffix(img, "/su") {
			ce.emitAlert(child.PID, "T1068", "Privilege Escalation Detected",
				fmt.Sprintf("%s(%d)[uid=%s] → %s(%d)[uid=%s]",
					parent.ImagePath, parent.PID, parent.User,
					child.ImagePath, child.PID, child.User),
				SevHigh, t)
		}
	}
}

func (ce *CorrelationEngine) checkLolbinRename(node *ProcessNode, t time.Time) {
	if node.OriginalName == "" || node.ImagePath == "" {
		return
	}
	imageName    := strings.ToLower(filepath.Base(node.ImagePath))
	originalName := strings.ToLower(filepath.Base(node.OriginalName))
	imageBase    := strings.TrimSuffix(imageName, filepath.Ext(imageName))
	originalBase := strings.TrimSuffix(originalName, filepath.Ext(originalName))
	if imageBase == originalBase {
		return
	}
	lolbins := map[string]bool{
		"cmd": true, "powershell": true, "powershell_ise": true,
		"wscript": true, "cscript": true, "mshta": true,
		"regsvr32": true, "rundll32": true, "msiexec": true,
		"certutil": true, "bitsadmin": true, "wmic": true,
		"net": true, "nltest": true, "sc": true,
		"schtasks": true, "at": true, "reg": true,
		"whoami": true, "ipconfig": true, "netstat": true,
	}
	if lolbins[originalBase] {
		ce.emitAlert(node.PID, "T1036.003", "LOLBin Rename Detected",
			fmt.Sprintf("Image '%s' has OriginalFileName '%s'",
				node.ImagePath, node.OriginalName),
			SevHigh, t)
	}
}

// checkPersistenceToolSpawn detects schtasks.exe, sc.exe, reg.exe, wmic.exe
// being spawned by the sandboxed process — a very reliable persistence indicator.
func (ce *CorrelationEngine) checkPersistenceToolSpawn(node *ProcessNode, t time.Time) {
	if node.ImagePath == "" {
		return
	}
	base := strings.ToLower(filepath.Base(node.ImagePath))
	cmdl := strings.ToLower(node.CommandLine)

	switch base {
	case "schtasks.exe":
		if strings.Contains(cmdl, "/create") || strings.Contains(cmdl, "-create") {
			ce.emitAlert(node.PID, "T1053.005", "Scheduled Task Created via schtasks.exe",
				fmt.Sprintf("PID(%d) spawned schtasks.exe with /create: %s", node.PID, node.CommandLine),
				SevHigh, t)
		}
	case "sc.exe":
		if strings.Contains(cmdl, "create") || strings.Contains(cmdl, "config") {
			ce.emitAlert(node.PID, "T1543.003", "Service Created/Modified via sc.exe",
				fmt.Sprintf("PID(%d) spawned sc.exe: %s", node.PID, node.CommandLine),
				SevHigh, t)
		}
	case "reg.exe":
		if strings.Contains(cmdl, "add") &&
			(strings.Contains(cmdl, `\run`) || strings.Contains(cmdl, `\services`)) {
			ce.emitAlert(node.PID, "T1547.001", "Registry Persistence via reg.exe",
				fmt.Sprintf("PID(%d) spawned reg.exe add on persistence key: %s", node.PID, node.CommandLine),
				SevHigh, t)
		}
	case "wmic.exe":
		if strings.Contains(cmdl, "process") && strings.Contains(cmdl, "call create") {
			ce.emitAlert(node.PID, "T1047", "WMI Execution via wmic.exe",
				fmt.Sprintf("PID(%d) spawned wmic.exe process call create: %s", node.PID, node.CommandLine),
				SevHigh, t)
		}
		if strings.Contains(cmdl, "subscription") || strings.Contains(cmdl, "eventfilter") {
			ce.emitAlert(node.PID, "T1547.003", "WMI Subscription via wmic.exe",
				fmt.Sprintf("PID(%d) spawned wmic.exe for WMI subscription: %s", node.PID, node.CommandLine),
				SevCritical, t)
		}
	case "at.exe":
		ce.emitAlert(node.PID, "T1053.002", "Scheduled Task via at.exe (legacy)",
			fmt.Sprintf("PID(%d) spawned at.exe: %s", node.PID, node.CommandLine),
			SevHigh, t)
	}
}

func (ce *CorrelationEngine) checkPersistenceToC2(pid int, objectPath, objType string, t time.Time) {
	lower := strings.ToLower(objectPath)
	var isPersistence bool
	if objType == "registry" {
		isPersistence = strings.Contains(lower, `\run`) ||
			strings.Contains(lower, `\runonce`) ||
			strings.Contains(lower, `\currentversion\services`) ||
			strings.Contains(lower, `\taskcache\`)
	} else if objType == "file" {
		isPersistence = strings.Contains(lower, `\startup\`) ||
			strings.Contains(lower, "/etc/cron") ||
			strings.Contains(lower, "/etc/systemd/system") ||
			strings.Contains(lower, "/etc/rc.local") ||
			strings.Contains(lower, "/.bashrc") ||
			strings.Contains(lower, "/.profile") ||
			strings.Contains(lower, "/etc/profile")
	}
	if !isPersistence {
		return
	}
	if conns := ce.netConns[pid]; len(conns) > 0 {
		ce.emitAlert(pid, "T1547", "Persistence + Outbound C2",
			fmt.Sprintf("PID(%d) wrote persistence '%s' with active connections %v",
				pid, objectPath, conns),
			SevHigh, t)
	}
}

func (ce *CorrelationEngine) checkC2Aftermath(pid int, dest string, t time.Time) {
	var item string
	for _, reg := range ce.regWrites[pid] {
		lower := strings.ToLower(reg)
		if strings.Contains(lower, `\run`) ||
			strings.Contains(lower, `\runonce`) ||
			strings.Contains(lower, `\currentversion\services`) {
			item = reg
			break
		}
	}
	if item == "" {
		for _, f := range ce.fileWrites[pid] {
			lower := strings.ToLower(f)
			if strings.Contains(lower, `\startup\`) ||
				strings.Contains(lower, "/etc/cron") ||
				strings.Contains(lower, "/etc/systemd/system") ||
				strings.Contains(lower, "/.bashrc") ||
				strings.Contains(lower, "/.profile") {
				item = f
				break
			}
		}
	}
	if item != "" {
		ce.emitAlert(pid, "T1071.001", "C2 Beaconing from Persistent Process",
			fmt.Sprintf("PID(%d) connected to %s after writing persistence '%s'",
				pid, dest, item),
			SevCritical, t)
	}
}

func (ce *CorrelationEngine) checkReflectiveInjection(pid int, imageName string, t time.Time) {
	ce.emitAlert(pid, "T1055.002", "Reflective DLL Injection",
		fmt.Sprintf("PID(%d) loaded '%s' with no disk backing", pid, imageName),
		SevCritical, t)
}

func (ce *CorrelationEngine) checkLSASSAccess(pid int, objectType, objectName string, t time.Time) {
	if !strings.Contains(strings.ToLower(objectName), "lsass") {
		return
	}
	ce.emitAlert(pid, "T1003.001", "LSASS Handle Access",
		fmt.Sprintf("PID(%d) opened '%s' handle to '%s'", pid, objectType, objectName),
		SevCritical, t)
}

func (ce *CorrelationEngine) emitAlert(pid int, ttp, technique, details string, severity int, t time.Time) {
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
	select {
	case ce.alerts <- alert:
	default:
	}
}

// ─── Utilities ────────────────────────────────────────────────────────────────

func buildDestString(ev Event) string {
	dest := ""
	if ip, ok := ev.Data["dest_ip"].(string); ok {
		dest = ip
		if port, ok := ev.Data["dest_port"].(int); ok && port != 0 {
			dest = fmt.Sprintf("%s:%d", dest, port)
		} else if portf, ok := ev.Data["dest_port"].(float64); ok {
			dest = fmt.Sprintf("%s:%d", dest, int(portf))
		}
	}
	if domain, ok := ev.Data["domain"].(string); ok && domain != "" {
		if dest == "" {
			dest = domain
		} else {
			dest = fmt.Sprintf("%s (%s)", dest, domain)
		}
	}
	return dest
}

func extractTargetPID(args map[string]interface{}) int {
	if v, ok := args["target_pid"].(int); ok {
		return v
	}
	if v, ok := args["target_pid"].(float64); ok {
		return int(v)
	}
	return 0
}
