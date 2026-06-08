//go:build !windows

package monitor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/lemas-sandbox/lemas/pkg/logger"
)

// ─── BPF event struct (must match monitoring.bpf.c exactly) ──────────────────
type bpfEvent struct {
	Timestamp  uint64
	PID        uint32
	PPID       uint32
	UID        uint32
	GID        uint32
	Comm       [16]byte
	Filename   [256]byte
	Type       uint32
	Target     [256]byte
	Flags      uint32
	DestPort   uint32
	SrcPort    uint32
	DestAddr   [16]byte
	SrcAddr    [16]byte
	AddrFamily uint8
	Pad        [3]byte
}

const (
	bpfEventProcessCreate = 1
	bpfEventProcessExit   = 2
	bpfEventFileWrite     = 3
	bpfEventFileDelete    = 4
	bpfEventNetConnect    = 5
	bpfEventFileOpen      = 6
	bpfEventPtrace        = 7
	bpfEventDNSQuery      = 8
)

type linuxProcessInfo struct {
	image        string
	cmdline      string
	processGUID  string
	originalName string
}

var mlog = logger.ForComponent("monitor-linux")

// ─── LinuxMonitor ─────────────────────────────────────────────────────────────
//
// Start() attempts eBPF first. If eBPF is unavailable (missing bytecode,
// no root, kernel too old) it automatically falls back to the /proc poller
// which works without any special privileges or kernel support.

type LinuxMonitor struct {
	jobID         string
	targetPID     int
	cancel        context.CancelFunc
	mu            sync.RWMutex
	monitoredPIDs map[int]bool
	processCache  map[int]linuxProcessInfo

	// eBPF handles — nil when running in proc-fallback mode
	collection *ebpf.Collection
	links      []link.Link
	ringReader *ringbuf.Reader

	correlator *CorrelationEngine
	mode       string // "ebpf" or "proc"
}

func NewMonitor() *LinuxMonitor {
	return &LinuxMonitor{
		monitoredPIDs: make(map[int]bool),
		processCache:  make(map[int]linuxProcessInfo),
	}
}

// Start begins telemetry collection.
// It tries eBPF first; on any failure it falls back to /proc polling silently.
func (m *LinuxMonitor) Start(ctx context.Context, jobID string, targetPID int, bus chan<- Event) error {
	m.jobID = jobID
	m.targetPID = targetPID

	m.mu.Lock()
	m.monitoredPIDs[targetPID] = true
	m.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.correlator = NewCorrelationEngine(jobID, bus)

	if err := m.startEBPF(ctx, targetPID, bus); err != nil {
		mlog.Warn().Err(err).Msg("eBPF unavailable — falling back to /proc monitor")
		m.startProcFallback(ctx, targetPID, bus)
		m.mode = "proc"
	} else {
		m.mode = "ebpf"
	}

	mlog.Info().
		Str("job_id", jobID).
		Int("pid", targetPID).
		Str("mode", m.mode).
		Msg("Linux monitor started")

	return nil
}

func (m *LinuxMonitor) Stop() error {
	m.cleanup()
	return nil
}

func (m *LinuxMonitor) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
	if m.ringReader != nil {
		_ = m.ringReader.Close()
	}
	for _, l := range m.links {
		_ = l.Close()
	}
	if m.collection != nil {
		m.collection.Close()
	}
}

func InjectSimulatedEvents(jobID string, filename string, bus chan<- Event) {}

// ─── eBPF startup ─────────────────────────────────────────────────────────────

// startEBPF loads and attaches the eBPF programs.
// Returns an error if anything fails — caller will fall back to /proc.
func (m *LinuxMonitor) startEBPF(ctx context.Context, targetPID int, bus chan<- Event) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("not root — eBPF requires CAP_SYS_ADMIN")
	}

	bytecode, err := loadBPFBytecode()
	if err != nil {
		return fmt.Errorf("load BPF bytecode: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bytecode))
	if err != nil {
		return fmt.Errorf("parse BPF ELF: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF programs: %w", err)
	}
	m.collection = coll

	// Seed root PID into target_pids map
	pidMap := coll.Maps["target_pids"]
	if pidMap != nil {
		var one valBool = 1
		key := uint32(targetPID)
		_ = pidMap.Put(&key, &one)
	}

	// Attach tracepoints
	type tp struct{ group, name, prog string }
	attachments := []tp{
		{"sched", "sched_process_exec", "handle_process_exec"},
		{"sched", "sched_process_exit", "handle_process_exit"},
		{"syscalls", "sys_enter_openat", "handle_sys_openat"},
		{"syscalls", "sys_enter_write", "handle_sys_write"},
		{"syscalls", "sys_enter_unlinkat", "handle_sys_unlinkat"},
		{"syscalls", "sys_enter_connect", "handle_sys_connect"},
		{"syscalls", "sys_enter_ptrace", "handle_sys_ptrace"},
	}
	for _, att := range attachments {
		prog := coll.Programs[att.prog]
		if prog == nil {
			m.cleanup()
			return fmt.Errorf("BPF program %q not found in ELF", att.prog)
		}
		l, err := link.Tracepoint(att.group, att.name, prog, nil)
		if err != nil {
			m.cleanup()
			return fmt.Errorf("attach tracepoint %s/%s: %w", att.group, att.name, err)
		}
		m.links = append(m.links, l)
	}

	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		m.cleanup()
		return fmt.Errorf("BPF ringbuf map 'events' not found")
	}
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		m.cleanup()
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	m.ringReader = rd

	go m.ebpfReadLoop(ctx, rd, bus, pidMap)
	return nil
}

// loadBPFBytecode returns the eBPF ELF bytes.
// Resolution order:
//  1. LEMAS_BPF_OBJECT env var — path to a compiled .o on disk (CI/production)
//  2. File next to this binary: <execDir>/monitoring.bpf.o
//  3. Embedded stub — returns errStubBytecode so caller falls back to /proc
func loadBPFBytecode() ([]byte, error) {
	// 1. Explicit override
	if path := os.Getenv("LEMAS_BPF_OBJECT"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("LEMAS_BPF_OBJECT=%q: %w", path, err)
		}
		mlog.Info().Str("path", path).Msg("loaded BPF object from LEMAS_BPF_OBJECT")
		return data, nil
	}

	// 2. Next to the running binary
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "monitoring.bpf.o")
		if data, err := os.ReadFile(candidate); err == nil {
			mlog.Info().Str("path", candidate).Msg("loaded BPF object from binary directory")
			return data, nil
		}
	}

	// 3. Stub — not a real ELF, will fail to parse
	if isStubBytecode(bpfBytecodeStub) {
		return nil, fmt.Errorf("no compiled BPF object found (stub embedded). " +
			"Run 'make ebpf' on Linux or set LEMAS_BPF_OBJECT=/path/to/monitoring.bpf.o")
	}

	return bpfBytecodeStub, nil
}

// isStubBytecode returns true when the slice is our placeholder ELF header stub.
// A real BPF ELF is always much larger (≥ several kilobytes).
func isStubBytecode(b []byte) bool {
	return len(b) < 256
}

func (m *LinuxMonitor) ebpfReadLoop(ctx context.Context, rd *ringbuf.Reader, bus chan<- Event, pidMap *ebpf.Map) {
	var raw bpfEvent
	for {
		select {
		case <-ctx.Done():
			return
		default:
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
				continue
			}
			m.handleBPFEvent(&raw, bus, pidMap)
		}
	}
}

// ─── /proc fallback monitor ───────────────────────────────────────────────────
//
// Works without root or kernel support. Polls /proc every 200ms to detect:
//   - New child processes spawned by the target tree
//   - File descriptor changes (open files → write detection)
//   - TCP connections via /proc/<pid>/net/tcp
//   - Process exit via polling
//
// Lower fidelity than eBPF but produces real, correct events — much better
// than zero events + a misleading report.

func (m *LinuxMonitor) startProcFallback(ctx context.Context, targetPID int, bus chan<- Event) {
	go m.procPollLoop(ctx, targetPID, bus)
}

func (m *LinuxMonitor) procPollLoop(ctx context.Context, rootPID int, bus chan<- Event) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	// Snapshot state so we can diff each tick
	type procState struct {
		cmdline string
		ppid    int
	}
	known := make(map[int]procState)
	knownConns := make(map[string]bool) // "pid:localPort:remoteIP:remotePort"
	knownFiles := make(map[string]bool) // "pid:fd:path"

	// Emit an initial process_create for the root PID itself
	m.emitProcCreate(rootPID, 0, bus)
	if info, err := readProcStat(rootPID); err == nil {
		known[rootPID] = procState{cmdline: readLinuxCmdline(rootPID), ppid: info.ppid}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// ── Discover monitored PIDs ───────────────────────────────────
			m.mu.RLock()
			pids := make([]int, 0, len(m.monitoredPIDs))
			for pid := range m.monitoredPIDs {
				pids = append(pids, pid)
			}
			m.mu.RUnlock()

			// ── Scan all /proc entries for new children ───────────────────
			allProcPIDs := listProcPIDs()
			for _, pid := range allProcPIDs {
				if _, alreadyKnown := known[pid]; alreadyKnown {
					continue
				}
				stat, err := readProcStat(pid)
				if err != nil {
					continue
				}
				m.mu.RLock()
				parentTracked := m.monitoredPIDs[stat.ppid]
				m.mu.RUnlock()
				if !parentTracked {
					continue
				}
				// New child of tracked process
				m.mu.Lock()
				m.monitoredPIDs[pid] = true
				m.mu.Unlock()
				known[pid] = procState{cmdline: readLinuxCmdline(pid), ppid: stat.ppid}
				m.emitProcCreate(pid, stat.ppid, bus)
			}

			// ── Per-tracked-PID checks ────────────────────────────────────
			for _, pid := range pids {
				// Process exit detection
				if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
					m.mu.Lock()
					delete(m.monitoredPIDs, pid)
					delete(m.processCache, pid)
					m.mu.Unlock()
					delete(known, pid)
					bus <- Event{
						JobID:     m.jobID,
						Timestamp: time.Now(),
						EventType: EventProcessExit,
						PID:       pid,
						Category:  CatProcess,
						Severity:  SevInfo,
						Data:      map[string]interface{}{"pid": pid, "exit_code": 0},
					}
					continue
				}

				// File write detection via /proc/<pid>/fd
				fdDir := fmt.Sprintf("/proc/%d/fd", pid)
				fds, err := os.ReadDir(fdDir)
				if err == nil {
					for _, fdEntry := range fds {
						fdPath := filepath.Join(fdDir, fdEntry.Name())
						target, err := os.Readlink(fdPath)
						if err != nil {
							continue
						}
						key := fmt.Sprintf("%d:%s:%s", pid, fdEntry.Name(), target)
						if knownFiles[key] {
							continue
						}
						knownFiles[key] = true
						// Only emit for non-socket, non-pipe paths that look like real files
						if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "/proc") {
							ev := Event{
								JobID:     m.jobID,
								Timestamp: time.Now(),
								EventType: EventFileWrite,
								PID:       pid,
								Category:  CatFile,
								Severity:  SevLow,
								Data: map[string]interface{}{
									"operation":     "OPEN",
									"path":          target,
									"TargetFilename": target,
								},
							}
							select {
							case bus <- ev:
							default:
							}
							m.correlator.ProcessEvent(ev)
						}
					}
				}

				// Network connection detection via /proc/<pid>/net/tcp and tcp6
				m.scanProcNetTCP(pid, knownConns, bus)
			}
		}
	}
}

// emitProcCreate synthesises a process_create event from /proc data.
func (m *LinuxMonitor) emitProcCreate(pid, ppid int, bus chan<- Event) {
	image := readLinuxExePath(pid)
	cmdline := readLinuxCmdline(pid)
	if cmdline == "" {
		cmdline = filepath.Base(image)
	}

	m.mu.RLock()
	parentInfo := m.processCache[ppid]
	m.mu.RUnlock()

	ts := time.Now()
	guid := buildLinuxProcessGUID(pid, ts)

	m.mu.Lock()
	m.processCache[pid] = linuxProcessInfo{
		image:        image,
		cmdline:      cmdline,
		processGUID:  guid,
		originalName: filepath.Base(image),
	}
	m.mu.Unlock()

	ev := Event{
		JobID:     m.jobID,
		Timestamp: ts,
		EventType: EventProcessCreate,
		PID:       pid,
		Category:  CatProcess,
		Severity:  SevInfo,
		Data: map[string]interface{}{
			"pid":              pid,
			"ppid":             ppid,
			"image_path":       image,
			"cmdline":          cmdline,
			"user":             readProcUIDUser(pid),
			"integrity_level":  integrityLevelFromUID(pid),
			"parent_image":     parentInfo.image,
			"parent_cmdline":   parentInfo.cmdline,
			"process_guid":     guid,
			"original_filename": filepath.Base(image),
			"is_injected":      false,
			// Sigma canonical names
			"Image":             image,
			"CommandLine":       cmdline,
			"ParentImage":       parentInfo.image,
			"ParentCommandLine": parentInfo.cmdline,
			"ParentProcessGuid": parentInfo.processGUID,
			"ProcessGuid":       guid,
			"OriginalFileName":  filepath.Base(image),
		},
	}

	select {
	case bus <- ev:
	default:
	}
	m.correlator.ProcessEvent(ev)
}

// scanProcNetTCP reads /proc/<pid>/net/tcp and /proc/<pid>/net/tcp6 to detect
// new outbound connections, emitting EventNetConnect for each new entry.
func (m *LinuxMonitor) scanProcNetTCP(pid int, known map[string]bool, bus chan<- Event) {
	for _, netFile := range []string{
		fmt.Sprintf("/proc/%d/net/tcp", pid),
		fmt.Sprintf("/proc/%d/net/tcp6", pid),
	} {
		f, err := os.Open(netFile)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // skip header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 {
				continue
			}
			// st=01 is ESTABLISHED
			if fields[3] != "01" {
				continue
			}
			localHex := fields[1]
			remoteHex := fields[2]
			connKey := fmt.Sprintf("%d:%s:%s", pid, localHex, remoteHex)
			if known[connKey] {
				continue
			}
			known[connKey] = true

			ip, port := parseProcNetHex(remoteHex)
			if ip == "" {
				continue
			}

			ev := Event{
				JobID:     m.jobID,
				Timestamp: time.Now(),
				EventType: EventNetConnect,
				PID:       pid,
				Category:  CatNetwork,
				Severity:  SevHigh,
				Data: map[string]interface{}{
					"protocol":         "TCP",
					"dest_ip":          ip,
					"dest_port":        port,
					"DestinationIp":    ip,
					"DestinationPort":  port,
					"Initiated":        true,
				},
			}
			if port == 53 {
				ev.EventType = EventNetDNS
				ev.Severity = SevLow
				ev.Data["protocol"] = "DNS"
				ev.Data["dns_query"] = inferDNSQueryFromProc(pid)
				ev.Data["domain"] = ev.Data["dns_query"]
			} else if port == 80 || port == 8080 {
				ev.Data["protocol"] = "HTTP"
			} else if port == 443 {
				ev.Data["protocol"] = "HTTPS"
			}
			select {
			case bus <- ev:
			default:
			}
			m.correlator.ProcessEvent(ev)
		}
		f.Close()
	}
}

// ─── eBPF event handler ───────────────────────────────────────────────────────

func (m *LinuxMonitor) handleBPFEvent(raw *bpfEvent, bus chan<- Event, pidMap *ebpf.Map) {
	pid  := int(raw.PID)
	ppid := int(raw.PPID)
	comm := cstring(raw.Comm[:])
	file := cstring(raw.Filename[:])
	tgt  := cstring(raw.Target[:])

	if raw.Type == bpfEventProcessCreate {
		m.mu.RLock()
		parentOK := m.monitoredPIDs[ppid]
		m.mu.RUnlock()
		if parentOK {
			m.mu.Lock()
			m.monitoredPIDs[pid] = true
			m.mu.Unlock()
			if pidMap != nil {
				var v valBool = 1
				k := uint32(pid)
				_ = pidMap.Put(&k, &v)
			}
		}
	}

	m.mu.RLock()
	monitored := m.monitoredPIDs[pid]
	m.mu.RUnlock()
	if !monitored {
		return
	}

	ev := Event{
		JobID:     m.jobID,
		Timestamp: time.Unix(0, int64(raw.Timestamp)),
		PID:       pid,
		Data:      make(map[string]interface{}),
	}

	switch raw.Type {
	case bpfEventProcessCreate:
		m.handleProcessCreate(&ev, raw, pid, ppid, comm, file, tgt, pidMap)

	case bpfEventProcessExit:
		ev.EventType = EventProcessExit
		ev.Category  = CatProcess
		ev.Severity  = SevInfo
		ev.Data["pid"] = pid
		ev.Data["exit_code"] = 0
		m.mu.Lock()
		delete(m.processCache, pid)
		m.mu.Unlock()

	case bpfEventFileWrite:
		path := resolveLinuxFDPath(pid, int(raw.Flags), file)
		ev.EventType = EventFileWrite
		ev.Category  = CatFile
		ev.Severity  = SevLow
		ev.Data["operation"]      = "WRITE"
		ev.Data["path"]           = path
		ev.Data["TargetFilename"] = path
		ev.Data["User"]           = linuxUIDToUser(raw.UID)

	case bpfEventFileDelete:
		ev.EventType = EventFileDelete
		ev.Category  = CatFile
		ev.Severity  = SevMedium
		ev.Data["operation"]      = "DELETE"
		ev.Data["path"]           = file
		ev.Data["TargetFilename"] = file
		ev.Data["User"]           = linuxUIDToUser(raw.UID)

	case bpfEventFileOpen:
		flags := int(raw.Flags)
		isWrite := (flags & 0x3) != 0
		isSusp  := isSuspiciousLinuxPath(file)
		if !isWrite && !isSusp {
			return
		}
		ev.EventType = EventFileWrite
		ev.Category  = CatFile
		ev.Severity  = SevLow
		ev.Data["operation"]      = "OPEN"
		ev.Data["path"]           = file
		ev.Data["TargetFilename"] = file
		ev.Data["flags"]          = flags

	case bpfEventNetConnect:
		ip, port := parseLinuxNetTarget(raw, tgt)
		ev.EventType = EventNetConnect
		ev.Category  = CatNetwork
		ev.Severity  = SevHigh
		ev.Data["protocol"]         = "TCP"
		ev.Data["dest_ip"]          = ip
		ev.Data["dest_port"]        = port
		ev.Data["DestinationIp"]    = ip
		ev.Data["DestinationPort"]  = port
		ev.Data["Initiated"]        = true
		if port == 80 || port == 8080 {
			ev.Data["protocol"] = "HTTP"
		} else if port == 443 {
			ev.Data["protocol"] = "HTTPS"
		}

	case bpfEventDNSQuery:
		ip, _ := parseLinuxNetTarget(raw, tgt)
		ev.EventType = EventNetDNS
		ev.Category  = CatNetwork
		ev.Severity  = SevLow
		queryName := inferDNSQueryFromProc(pid)
		ev.Data["dns_query"]  = queryName
		ev.Data["domain"]     = queryName
		ev.Data["dest_ip"]    = ip
		ev.Data["dest_port"]  = 53
		ev.Data["QueryName"]  = queryName
		ev.Data["protocol"]   = "DNS"

	case bpfEventPtrace:
		targetPID := parsePtraceTarget(tgt)
		ev.EventType = EventAPICall
		ev.Category  = CatAPI
		ev.Severity  = SevCritical
		ev.Data["api_name"]   = "ptrace"
		ev.Data["target_pid"] = targetPID
		ev.Data["flags"]      = raw.Flags
		ev.Data["mitre_ttp"]  = "T1055.008"

	default:
		return
	}

	select {
	case bus <- ev:
	default:
	}
	m.correlator.ProcessEvent(ev)
}

// handleProcessCreate builds a fully enriched process_create event from eBPF data.
func (m *LinuxMonitor) handleProcessCreate(
	ev *Event, raw *bpfEvent,
	pid, ppid int, comm, file, argv0 string,
	pidMap *ebpf.Map,
) {
	cmdline := readLinuxCmdline(pid)
	if cmdline == "" {
		cmdline = comm
	}
	image := file
	if image == "" || strings.HasPrefix(image, "/proc/self") {
		image = readLinuxExePath(pid)
	}

	m.mu.RLock()
	parentInfo := m.processCache[ppid]
	m.mu.RUnlock()

	processGUID  := buildLinuxProcessGUID(pid, ev.Timestamp)
	hashes       := hashLinuxBinary(image)
	originalName := filepath.Base(image)
	userStr      := linuxUIDToUser(raw.UID)

	integrityLevel := "User"
	if raw.UID == 0 {
		integrityLevel = "System"
	}

	m.mu.Lock()
	m.processCache[pid] = linuxProcessInfo{
		image:        image,
		cmdline:      cmdline,
		processGUID:  processGUID,
		originalName: originalName,
	}
	m.mu.Unlock()

	ev.EventType = EventProcessCreate
	ev.Category  = CatProcess
	ev.Severity  = SevInfo

	ev.Data["pid"]               = pid
	ev.Data["ppid"]              = ppid
	ev.Data["image_path"]        = image
	ev.Data["cmdline"]           = cmdline
	ev.Data["user"]              = userStr
	ev.Data["integrity_level"]   = integrityLevel
	ev.Data["parent_image"]      = parentInfo.image
	ev.Data["parent_cmdline"]    = parentInfo.cmdline
	ev.Data["process_guid"]      = processGUID
	ev.Data["original_filename"] = originalName
	ev.Data["is_injected"]       = false
	ev.Data["Image"]             = image
	ev.Data["CommandLine"]       = cmdline
	ev.Data["ParentImage"]       = parentInfo.image
	ev.Data["ParentCommandLine"] = parentInfo.cmdline
	ev.Data["ParentProcessGuid"] = parentInfo.processGUID
	ev.Data["User"]              = userStr
	ev.Data["IntegrityLevel"]    = integrityLevel
	ev.Data["ProcessGuid"]       = processGUID
	ev.Data["OriginalFileName"]  = originalName
	ev.Data["LogonId"]           = fmt.Sprintf("0x%x", raw.UID)

	if hashes != nil {
		ev.Data["Hashes"] = hashes
		ev.Data["sha256"] = hashes["sha256"]
		ev.Data["md5"]    = hashes["md5"]
		ev.Data["SHA256"] = hashes["sha256"]
		ev.Data["MD5"]    = hashes["md5"]
	}

	if strings.HasPrefix(image, "/usr/") || strings.HasPrefix(image, "/bin/") ||
		strings.HasPrefix(image, "/sbin/") || strings.HasPrefix(image, "/lib/") {
		ev.Data["Signed"]          = "true"
		ev.Data["Signature"]       = "System"
		ev.Data["SignatureStatus"] = "Valid"
	} else {
		ev.Data["Signed"]          = "false"
		ev.Data["Signature"]       = ""
		ev.Data["SignatureStatus"] = "Unsigned"
	}
}

// ─── /proc helpers ────────────────────────────────────────────────────────────

type procStatInfo struct{ ppid int }

func readProcStat(pid int) (procStatInfo, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procStatInfo{}, err
	}
	// stat format: pid (comm) state ppid ...
	// comm can contain spaces and parentheses, so find the last ')' first.
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 {
		return procStatInfo{}, fmt.Errorf("malformed stat")
	}
	fields := strings.Fields(s[idx+1:])
	if len(fields) < 2 {
		return procStatInfo{}, fmt.Errorf("stat too short")
	}
	var ppid int
	fmt.Sscanf(fields[1], "%d", &ppid)
	return procStatInfo{ppid: ppid}, nil
}

// listProcPIDs returns all numeric PIDs currently in /proc.
func listProcPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// parseProcNetHex decodes a "AABBCCDD:PPPP" hex entry from /proc/net/tcp.
// Returns (dotted-decimal IP, port).
func parseProcNetHex(hex string) (string, int) {
	parts := strings.Split(hex, ":")
	if len(parts) != 2 {
		return "", 0
	}
	var ipHex uint32
	var portHex uint32
	fmt.Sscanf(parts[0], "%X", &ipHex)
	fmt.Sscanf(parts[1], "%X", &portHex)
	// /proc/net/tcp stores IP in little-endian
	ip := fmt.Sprintf("%d.%d.%d.%d",
		ipHex&0xFF,
		(ipHex>>8)&0xFF,
		(ipHex>>16)&0xFF,
		(ipHex>>24)&0xFF)
	return ip, int(portHex)
}

// readProcUIDUser reads the UID from /proc/<pid>/status and maps it to username.
func readProcUIDUser(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var uid uint32
				fmt.Sscanf(fields[1], "%d", &uid)
				return linuxUIDToUser(uid)
			}
		}
	}
	return ""
}

// integrityLevelFromUID returns "System" for root, "User" otherwise.
func integrityLevelFromUID(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "User"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "0" {
				return "System"
			}
			return "User"
		}
	}
	return "User"
}

// ─── Shared helpers (used by both eBPF and /proc paths) ──────────────────────

func cstring(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}

func readLinuxCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
}

func readLinuxExePath(pid int) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return p
}

func resolveLinuxFDPath(pid, fd int, bpfPath string) string {
	lnk := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	if p, err := os.Readlink(lnk); err == nil {
		return p
	}
	if bpfPath != "" && !strings.HasPrefix(bpfPath, "/proc/") {
		return bpfPath
	}
	return lnk
}

func parseLinuxNetTarget(raw *bpfEvent, tgt string) (string, int) {
	port := int(raw.DestPort)
	var ip string
	if raw.AddrFamily == 2 {
		ip = fmt.Sprintf("%d.%d.%d.%d",
			raw.DestAddr[0], raw.DestAddr[1],
			raw.DestAddr[2], raw.DestAddr[3])
	} else if raw.AddrFamily == 10 {
		ip = fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			uint16(raw.DestAddr[0])<<8|uint16(raw.DestAddr[1]),
			uint16(raw.DestAddr[2])<<8|uint16(raw.DestAddr[3]),
			uint16(raw.DestAddr[4])<<8|uint16(raw.DestAddr[5]),
			uint16(raw.DestAddr[6])<<8|uint16(raw.DestAddr[7]),
			uint16(raw.DestAddr[8])<<8|uint16(raw.DestAddr[9]),
			uint16(raw.DestAddr[10])<<8|uint16(raw.DestAddr[11]),
			uint16(raw.DestAddr[12])<<8|uint16(raw.DestAddr[13]),
			uint16(raw.DestAddr[14])<<8|uint16(raw.DestAddr[15]))
	} else {
		ip = strings.Split(tgt, ":")[0]
	}
	return ip, port
}

func parsePtraceTarget(tgt string) int {
	var n int
	fmt.Sscanf(tgt, "target_pid=%d", &n)
	return n
}

func inferDNSQueryFromProc(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/net/dns", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var last string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if fields := strings.Fields(line); len(fields) > 0 {
				last = fields[0]
			}
		}
	}
	return last
}

func linuxUIDToUser(uid uint32) string {
	if uid == 0 {
		return "root"
	}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return fmt.Sprintf("%d", uid)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	uidStr := fmt.Sprintf("%d", uid)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) >= 3 && fields[2] == uidStr {
			return fields[0]
		}
	}
	return uidStr
}

func isSuspiciousLinuxPath(path string) bool {
	suspects := []string{
		"/tmp/", "/dev/shm/", "/var/tmp/",
		"/etc/cron", "/etc/systemd/system/",
		"/.ssh/", "/etc/passwd", "/etc/shadow",
		"/proc/", "/sys/",
	}
	lower := strings.ToLower(path)
	for _, s := range suspects {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func buildLinuxProcessGUID(pid int, spawnTime time.Time) string {
	epoch := uint32(spawnTime.Unix() & 0xFFFFFFFF)
	return fmt.Sprintf("{%08X-%04X-%08X}", epoch, pid&0xFFFF, epoch^uint32(pid))
}

func hashLinuxBinary(imagePath string) map[string]string {
	if imagePath == "" {
		return nil
	}
	lower := strings.ToLower(imagePath)
	if strings.HasPrefix(lower, "/usr/") || strings.HasPrefix(lower, "/bin/") ||
		strings.HasPrefix(lower, "/sbin/") || strings.HasPrefix(lower, "/lib") {
		return nil
	}
	data, err := os.ReadFile(imagePath)
	if err != nil {
		return nil
	}
	s := fmt.Sprintf("%x", sha256.Sum256(data))
	md := fmt.Sprintf("%x", md5.Sum(data))
	return map[string]string{
		"sha256": s, "SHA256": s,
		"md5": md, "MD5": md,
	}
}

type valBool uint8

// bpfBytecodeStub is a minimal ELF header placeholder.
// It is intentionally too small to be a valid BPF object (< 256 bytes)
// so isStubBytecode() catches it and triggers the /proc fallback.
var bpfBytecodeStub = []byte{
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0xf7, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}
