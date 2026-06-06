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
)

// ─── BPF event struct (must match monitoring.bpf.c exactly) ──────────────────
//
// If the BPF C source is recompiled, regenerate this struct via:
//   go run github.com/cilium/ebpf/cmd/bpf2go Monitor bpf/monitoring.bpf.c
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

// Event type constants matching the BPF C source.
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

// linuxProcessInfo caches per-process metadata for parent enrichment.
type linuxProcessInfo struct {
	image        string
	cmdline      string
	processGUID  string
	originalName string // ELF .note or /proc cmdline fallback
}

type LinuxMonitor struct {
	jobID         string
	targetPID     int
	cancel        context.CancelFunc
	mu            sync.RWMutex
	monitoredPIDs map[int]bool
	processCache  map[int]linuxProcessInfo
	collection    *ebpf.Collection
	links         []link.Link
	ringReader    *ringbuf.Reader
	correlator    *CorrelationEngine
}

func NewMonitor() *LinuxMonitor {
	return &LinuxMonitor{
		monitoredPIDs: make(map[int]bool),
		processCache:  make(map[int]linuxProcessInfo),
	}
}

func (m *LinuxMonitor) Start(ctx context.Context, jobID string, targetPID int, bus chan<- Event) error {
	m.jobID = jobID
	m.targetPID = targetPID

	if os.Geteuid() != 0 {
		return fmt.Errorf("root required: eBPF monitoring needs root/CAP_SYS_ADMIN")
	}

	m.mu.Lock()
	m.monitoredPIDs[targetPID] = true
	m.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.correlator = NewCorrelationEngine(jobID, bus)

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytecode))
	if err != nil {
		return fmt.Errorf("failed to load BPF spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to load BPF programs: %v", err)
	}
	m.collection = coll

	// Seed initial PID
	pidMap := coll.Maps["target_pids"]
	if pidMap != nil {
		var active valBool = 1
		var key uint32 = uint32(targetPID)
		_ = pidMap.Put(&key, &active)
	}

	// Attach tracepoints
	attachments := []struct{ group, name, prog string }{
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
			return fmt.Errorf("BPF program %s not found", att.prog)
		}
		l, err := link.Tracepoint(att.group, att.name, prog, nil)
		if err != nil {
			m.cleanup()
			return fmt.Errorf("failed to attach %s/%s: %v", att.group, att.name, err)
		}
		m.links = append(m.links, l)
	}

	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		m.cleanup()
		return fmt.Errorf("BPF events ring buffer not found")
	}
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		m.cleanup()
		return fmt.Errorf("ringbuf reader: %v", err)
	}
	m.ringReader = rd

	go func() {
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
	}()
	return nil
}

func (m *LinuxMonitor) Stop() error { m.cleanup(); return nil }

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

// ─── Event handler ────────────────────────────────────────────────────────────

func (m *LinuxMonitor) handleBPFEvent(raw *bpfEvent, bus chan<- Event, pidMap *ebpf.Map) {
	pid  := int(raw.PID)
	ppid := int(raw.PPID)
	comm := cstring(raw.Comm[:])
	file := cstring(raw.Filename[:])
	tgt  := cstring(raw.Target[:])

	// Propagate child tracking for process_create
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
				var k uint32 = uint32(pid)
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
		ev.Data["operation"]     = "WRITE"
		ev.Data["path"]          = path
		ev.Data["TargetFilename"] = path
		ev.Data["User"]          = linuxUIDToUser(raw.UID)

	case bpfEventFileDelete:
		ev.EventType = EventFileDelete
		ev.Category  = CatFile
		ev.Severity  = SevMedium
		ev.Data["operation"]     = "DELETE"
		ev.Data["path"]          = file
		ev.Data["TargetFilename"] = file
		ev.Data["User"]          = linuxUIDToUser(raw.UID)

	case bpfEventFileOpen:
		// Only emit suspicious opens (write flags, suspicious paths)
		flags := int(raw.Flags)
		isWrite := (flags & 0x3) != 0 // O_WRONLY or O_RDWR
		isSusp  := isSuspiciousLinuxPath(file)
		if !isWrite && !isSusp {
			return
		}
		ev.EventType = EventFileWrite
		ev.Category  = CatFile
		ev.Severity  = SevLow
		ev.Data["operation"]     = "OPEN"
		ev.Data["path"]          = file
		ev.Data["TargetFilename"] = file
		ev.Data["flags"]         = flags

	case bpfEventNetConnect:
		ip, port := parseLinuxNetTarget(raw, tgt)
		ev.EventType = EventNetConnect
		ev.Category  = CatNetwork
		ev.Severity  = SevHigh
		ev.Data["protocol"]          = "TCP"
		ev.Data["dest_ip"]           = ip
		ev.Data["dest_port"]         = port
		ev.Data["DestinationIp"]      = ip
		ev.Data["DestinationPort"]    = port
		ev.Data["Initiated"]         = true
		if port == 80 || port == 8080 {
			ev.Data["protocol"] = "HTTP"
		} else if port == 443 {
			ev.Data["protocol"] = "HTTPS"
		}

	case bpfEventDNSQuery:
		// DNS queries on port 53 — filename contains dest IP, target contains port
		ip, _ := parseLinuxNetTarget(raw, tgt)
		ev.EventType = EventNetDNS
		ev.Category  = CatNetwork
		ev.Severity  = SevLow
		// Best effort: we can't capture the query name from a connect() tracepoint alone.
		// Read /proc/<pid>/net/dns or use the comm as a hint.
		queryName := inferDNSQueryFromProc(pid)
		ev.Data["dns_query"]  = queryName
		ev.Data["domain"]     = queryName
		ev.Data["dest_ip"]    = ip
		ev.Data["dest_port"]  = 53
		ev.Data["QueryName"]  = queryName
		ev.Data["protocol"]   = "DNS"

	case bpfEventPtrace:
		// Linux process injection via ptrace
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

// handleProcessCreate builds a fully enriched process_create event.
func (m *LinuxMonitor) handleProcessCreate(
	ev *Event, raw *bpfEvent,
	pid, ppid int, comm, file, argv0 string,
	pidMap *ebpf.Map,
) {
	// Full cmdline from /proc/<pid>/cmdline
	cmdline := readLinuxCmdline(pid)
	if cmdline == "" {
		cmdline = comm
	}
	// Executable path: prefer bpf filename, fall back to /proc/<pid>/exe
	image := file
	if image == "" || strings.HasPrefix(image, "/proc/self") {
		image = readLinuxExePath(pid)
	}

	// Parent info from cache
	m.mu.RLock()
	parentInfo := m.processCache[ppid]
	m.mu.RUnlock()

	// ProcessGuid
	processGUID := buildLinuxProcessGUID(pid, ev.Timestamp)

	// Hashes (only small non-system binaries)
	hashes := hashLinuxBinary(image)

	// OriginalFileName — for Linux ELF this is just the basename of the image
	originalName := filepath.Base(image)

	// User string
	userStr := linuxUIDToUser(raw.UID)

	// Integrity level analog: UID 0 = System, else User
	integrityLevel := "User"
	if raw.UID == 0 {
		integrityLevel = "System"
	}

	// Cache for children
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

	// Internal field names (used by correlation engine)
	ev.Data["pid"]            = pid
	ev.Data["ppid"]           = ppid
	ev.Data["image_path"]     = image
	ev.Data["cmdline"]        = cmdline
	ev.Data["user"]           = userStr
	ev.Data["integrity_level"] = integrityLevel
	ev.Data["parent_image"]   = parentInfo.image
	ev.Data["parent_cmdline"] = parentInfo.cmdline
	ev.Data["process_guid"]   = processGUID
	ev.Data["original_filename"] = originalName
	ev.Data["is_injected"]    = false

	// Sigma canonical field names (exact case from community rules)
	ev.Data["Image"]              = image
	ev.Data["CommandLine"]        = cmdline
	ev.Data["ParentImage"]        = parentInfo.image
	ev.Data["ParentCommandLine"]  = parentInfo.cmdline
	ev.Data["ParentProcessGuid"]  = parentInfo.processGUID
	ev.Data["User"]               = userStr
	ev.Data["IntegrityLevel"]     = integrityLevel
	ev.Data["ProcessGuid"]        = processGUID
	ev.Data["OriginalFileName"]   = originalName
	ev.Data["LogonId"]            = fmt.Sprintf("0x%x", raw.UID) // UID as LogonId analog
	// Hashes
	if hashes != nil {
		ev.Data["Hashes"]  = hashes
		ev.Data["sha256"]  = hashes["sha256"]
		ev.Data["md5"]     = hashes["md5"]
		ev.Data["SHA256"]  = hashes["sha256"]
		ev.Data["MD5"]     = hashes["md5"]
	}
	// Linux has no Authenticode — mark as signed only for system paths
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

// ─── Linux enrichment helpers ─────────────────────────────────────────────────

// cstring converts a null-padded byte array to a Go string.
func cstring(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}

// readLinuxCmdline reads the full command line from /proc/<pid>/cmdline.
func readLinuxCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// cmdline fields are NUL-separated
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
}

// readLinuxExePath resolves the executable path via /proc/<pid>/exe symlink.
func readLinuxExePath(pid int) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return p
}

// resolveLinuxFDPath attempts to resolve a file descriptor to a path.
// Falls back to the /proc/self/fd/<fd> placeholder emitted by BPF.
func resolveLinuxFDPath(pid, fd int, bpfPath string) string {
	link := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	if p, err := os.Readlink(link); err == nil {
		return p
	}
	// BPF may have given us a cached path
	if bpfPath != "" && !strings.HasPrefix(bpfPath, "/proc/") {
		return bpfPath
	}
	return link
}

// parseLinuxNetTarget extracts IP and port from a bpfEvent network event.
func parseLinuxNetTarget(raw *bpfEvent, tgt string) (string, int) {
	port := int(raw.DestPort)
	var ip string

	if raw.AddrFamily == 2 { // AF_INET
		ip = fmt.Sprintf("%d.%d.%d.%d",
			raw.DestAddr[0], raw.DestAddr[1],
			raw.DestAddr[2], raw.DestAddr[3])
	} else if raw.AddrFamily == 10 { // AF_INET6
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
		// Parse "IP.IP.IP.IP" from BPF filename field
		ip = strings.Split(tgt, ":")[0]
	}
	return ip, port
}

// parsePtraceTarget extracts the target PID from a ptrace BPF event target string.
func parsePtraceTarget(tgt string) int {
	var n int
	fmt.Sscanf(tgt, "target_pid=%d", &n)
	return n
}

// inferDNSQueryFromProc reads the most recent DNS query name from /proc/<pid>/net/dns
// or the process name as a best-effort fallback.
func inferDNSQueryFromProc(pid int) string {
	// /proc/net/dns does not exist on all kernels; best effort
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
			fields := strings.Fields(line)
			if len(fields) > 0 {
				last = fields[0]
			}
		}
	}
	return last
}

// linuxUIDToUser maps a UID to a username by reading /etc/passwd.
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

// isSuspiciousLinuxPath returns true for paths that are interesting to analysts.
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

// buildLinuxProcessGUID builds a deterministic process GUID from PID + spawn time.
func buildLinuxProcessGUID(pid int, spawnTime time.Time) string {
	epoch := uint32(spawnTime.Unix() & 0xFFFFFFFF)
	return fmt.Sprintf("{%08X-%04X-%08X}", epoch, pid&0xFFFF, epoch^uint32(pid))
}

// hashLinuxBinary computes SHA256+MD5 for a Linux binary.
// Skips system binaries in /usr, /bin, /sbin for performance.
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
	m := fmt.Sprintf("%x", md5.Sum(data))
	return map[string]string{
		"sha256": s, "SHA256": s,
		"md5": m, "MD5": m,
	}
}

type valBool uint8

// bpfBytecode is the pre-compiled eBPF ELF.
// Replace with the real compiled object for production:
//
//	clang -target bpf -O2 -Wall -g -c bpf/monitoring.bpf.c -o bpf/monitoring.bpf.o
//	xxd -i bpf/monitoring.bpf.o > bpf_bytecode.go
//
// The stub below allows the Go code to compile and link on all platforms.
// At runtime on Linux it will fail to load (expected until real ELF is embedded).
var bpfBytecode = []byte{
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0xf7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}
