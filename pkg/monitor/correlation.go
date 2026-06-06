package monitor

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// processKey uniquely identifies a process instance resistant to PID reuse.
// Using PID alone is unsafe because OSes recycle PIDs.
type processKey struct {
	PID       int
	SpawnTime int64 // Unix nanoseconds
}

// CorrelationEngine maintains an in-memory behavior graph.
type CorrelationEngine struct {
	mu sync.RWMutex

	jobID string

	// Process graph — keyed by processKey (PID+SpawnTime) to resist PID reuse.
	processes map[processKey]*ProcessNode
	// pidToKey maps bare PID → most-recent processKey (for lookup by PID only).
	pidToKey map[int]processKey

	// Behavioral state maps — keyed by PID (fast path; PID reuse within a single
	// sandbox session is extremely unlikely given short analysis windows).
	fileWrites   map[int][]string
	regWrites    map[int][]string
	netConns     map[int][]string
	apiCalls     map[int][]string
	injectionMap map[int]map[int]bool

	// Extended telemetry maps (Tasks A/B/C)
	dllLoads     map[int][]string
	dnsQueries   map[int][]string
	handleAccess map[int][]string
	scriptBlocks map[int][]string

	alerts chan<- Event
}

type ProcessNode struct {
	PID           int
	PPID          int
	ImagePath     string
	CommandLine   string
	OriginalName  string // PE/ELF OriginalFileName (lolbin rename detection)
	SpawnTime     time.Time
	User          string
	Integrity     string
	ProcessGUID   string
	LogonID       string
}

func NewCorrelationEngine(jobID string, alerts chan<- Event) *CorrelationEngine {
	return &CorrelationEngine{
		jobID:        jobID,
		processes:    make(map[processKey]*ProcessNode),
		pidToKey:     make(map[int]processKey),
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

	case EventProcessExit:
		if key, ok := ce.pidToKey[ev.PID]; ok {
			delete(ce.processes, key)
			delete(ce.pidToKey, ev.PID)
		}
		// Clean behavioural state — process is gone
		delete(ce.fileWrites, ev.PID)
		delete(ce.regWrites, ev.PID)
		delete(ce.netConns, ev.PID)
		delete(ce.apiCalls, ev.PID)
		delete(ce.injectionMap, ev.PID)
		delete(ce.dllLoads, ev.PID)
		delete(ce.dnsQueries, ev.PID)
		delete(ce.handleAccess, ev.PID)
		delete(ce.scriptBlocks, ev.PID)

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
			ce.checkProcessInjection(ev.PID, apiName, ev.Data, ev.Timestamp)
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
			ce.checkProcessInjection(ev.PID, "CreateRemoteThread", ev.Data, ev.Timestamp)
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
	}
}

// ─── Node builder ─────────────────────────────────────────────────────────────

func (ce *CorrelationEngine) buildProcessNode(ev Event) *ProcessNode {
	node := &ProcessNode{
		PID:       ev.PID,
		SpawnTime: ev.Timestamp,
	}
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
	// OriginalFileName — from both lowercase and Sigma-case keys
	if v, ok := ev.Data["original_filename"].(string); ok {
		node.OriginalName = v
	} else if v, ok := ev.Data["OriginalFileName"].(string); ok {
		node.OriginalName = v
	}
	return node
}

// ─── Correlation checks ───────────────────────────────────────────────────────

// checkPrivilegeEscalation detects integrity level or UID privilege escalation.
func (ce *CorrelationEngine) checkPrivilegeEscalation(child *ProcessNode, t time.Time) {
	parentKey, ok := ce.pidToKey[child.PPID]
	if !ok {
		return
	}
	parent, ok := ce.processes[parentKey]
	if !ok {
		return
	}

	// Windows integrity level
	if parent.Integrity != "" && child.Integrity != "" {
		pLow  := strings.Contains(strings.ToLower(parent.Integrity), "medium") ||
			strings.Contains(strings.ToLower(parent.Integrity), "low")
		cHigh := strings.Contains(strings.ToLower(child.Integrity), "high") ||
			strings.Contains(strings.ToLower(child.Integrity), "system")
		if pLow && cHigh &&
			!strings.Contains(strings.ToLower(child.ImagePath), "consent.exe") {
			ce.emitAlert(child.PID, "T1068", "Privilege Escalation Detected",
				fmt.Sprintf("%s(%d)[%s] spawned %s(%d)[%s]",
					parent.ImagePath, parent.PID, parent.Integrity,
					child.ImagePath, child.PID, child.Integrity),
				SevHigh, t)
		}
	}

	// Linux UID escalation
	if parent.User != "" && child.User != "" {
		pNonRoot := parent.User != "root" && parent.User != "0"
		cRoot    := child.User == "root" || child.User == "0"
		img := strings.ToLower(child.ImagePath)
		if pNonRoot && cRoot &&
			!strings.HasSuffix(img, "/sudo") && !strings.HasSuffix(img, "/su") {
			ce.emitAlert(child.PID, "T1068", "Privilege Escalation Detected",
				fmt.Sprintf("%s(%d)[uid=%s] spawned %s(%d)[uid=%s]",
					parent.ImagePath, parent.PID, parent.User,
					child.ImagePath, child.PID, child.User),
				SevHigh, t)
		}
	}
}

// checkLolbinRename detects renamed LOLBins: Image filename ≠ OriginalFileName.
// e.g. cmd.exe renamed to svchost.exe would show Image=svchost.exe, OriginalFileName=cmd.exe.
// Mapped to T1036.003 (Masquerading: Rename System Utilities).
func (ce *CorrelationEngine) checkLolbinRename(node *ProcessNode, t time.Time) {
	if node.OriginalName == "" || node.ImagePath == "" {
		return
	}
	imageName    := strings.ToLower(filepath.Base(node.ImagePath))
	originalName := strings.ToLower(filepath.Base(node.OriginalName))

	// Strip extension for comparison
	imageBase    := strings.TrimSuffix(imageName, filepath.Ext(imageName))
	originalBase := strings.TrimSuffix(originalName, filepath.Ext(originalName))

	if imageBase == originalBase {
		return // names match — normal
	}

	// Known LOLBins worth flagging when renamed
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
			fmt.Sprintf("Process image '%s' has OriginalFileName '%s' — possible renamed system utility",
				node.ImagePath, node.OriginalName),
			SevHigh, t)
	}
}

// checkProcessInjection tracks VirtualAllocEx+WriteProcessMemory+CreateRemoteThread
// and ptrace ATTACH+POKETEXT chains.
func (ce *CorrelationEngine) checkProcessInjection(sourcePID int, apiName string, args map[string]interface{}, t time.Time) {
	targetPID := extractTargetPID(args)
	if targetPID == 0 || targetPID == sourcePID {
		return
	}
	if ce.injectionMap[sourcePID] == nil {
		ce.injectionMap[sourcePID] = make(map[int]bool)
	}
	lower := strings.ToLower(apiName)
	if strings.Contains(lower, "writeprocessmemory") ||
		strings.Contains(lower, "virtualallocex") ||
		strings.Contains(lower, "ptrace_poketext") {
		ce.injectionMap[sourcePID][targetPID] = true
	}
	if strings.Contains(lower, "createremotethread") ||
		strings.Contains(lower, "ptrace_attach") ||
		strings.Contains(lower, "ptrace_seize") {
		if ce.injectionMap[sourcePID][targetPID] {
			ce.emitAlert(sourcePID, "T1055.001", "Process Injection Attack Sequence",
				fmt.Sprintf("PID(%d) performed alloc/write then %s on PID(%d)",
					sourcePID, apiName, targetPID),
				SevCritical, t)
		} else {
			ce.emitAlert(sourcePID, "T1055", "Suspicious Cross-Process API",
				fmt.Sprintf("PID(%d) called %s on PID(%d)",
					sourcePID, apiName, targetPID),
				SevHigh, t)
		}
	}
}

// checkPersistenceToC2 fires when a persistence write is followed by a network connection.
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
		ce.emitAlert(pid, "T1547", "Persistence and Outbound Connection",
			fmt.Sprintf("PID(%d) wrote persistence '%s' and has active connections %v",
				pid, objectPath, conns),
			SevHigh, t)
	}
}

// checkC2Aftermath fires when outbound network follows earlier persistence.
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
			fmt.Sprintf("PID(%d) connected to %s after writing persistence in '%s'",
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
