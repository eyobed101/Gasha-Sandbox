//go:build windows

package isolation

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── Win32 proc bindings ──────────────────────────────────────────────────────

var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procCreateJobObjectW         = modKernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = modKernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = modKernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = modKernel32.NewProc("TerminateJobObject")
	procCreateProcessW           = modKernel32.NewProc("CreateProcessW")
	procResumeThread             = modKernel32.NewProc("ResumeThread")
	procCreatePipe               = modKernel32.NewProc("CreatePipe")
	procSetHandleInformation     = modKernel32.NewProc("SetHandleInformation")
)

// ─── Win32 constants ──────────────────────────────────────────────────────────

const (
	// Job object info classes
	jobObjectExtendedLimitInformation  = 9
	jobObjectCpuRateControlInformation = 15

	// Job object limit flags
	jobLimitKillOnJobClose  = 0x00002000
	jobLimitJobMemory       = 0x00000400
	jobLimitProcessMemory   = 0x00000100
	jobLimitActiveProcess   = 0x00000008

	// CPU rate control flags
	jobCPURateControlEnable    = 0x0001
	jobCPURateControlHardLimit = 0x0004

	// Process creation flags
	createSuspended             = 0x00000004
	createNewConsole            = 0x00000010
	createNoWindow              = 0x08000000
	inheritParentAffinity       = 0x00010000

	// Handle flags
	handleFlagInherit = 0x00000001

	// Process access rights
	processAllAccess = 0x1F0FFF

	// ResumeThread returns 0xFFFFFFFF on error
	resumeThreadError = ^uintptr(0)
)

// ─── Win32 structs ────────────────────────────────────────────────────────────

type jobObjectBasicLimitInfo struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInfo
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type jobObjectCPURateControlInfo struct {
	ControlFlags uint32
	CpuRate      uint32
}

// STARTUPINFOW matches the Win32 STARTUPINFOW layout exactly.
type startupInfoW struct {
	Cb              uint32
	_               *uint16 // lpReserved
	Desktop         *uint16
	Title           *uint16
	X               uint32
	Y               uint32
	XSize           uint32
	YSize           uint32
	XCountChars     uint32
	YCountChars     uint32
	FillAttribute   uint32
	Flags           uint32
	ShowWindow      uint16
	_               uint16 // cbReserved2
	_               *byte  // lpReserved2
	StdInput        syscall.Handle
	StdOutput       syscall.Handle
	StdError        syscall.Handle
}

// PROCESS_INFORMATION matches the Win32 PROCESS_INFORMATION layout.
type processInformation struct {
	Process   syscall.Handle
	Thread    syscall.Handle
	ProcessID uint32
	ThreadID  uint32
}

const startfUseStdHandles = 0x00000100

// ─── WindowsJobProcess ────────────────────────────────────────────────────────

// WindowsJobProcess implements isolation.Process.
// The sandboxed process is spawned suspended, assigned to a Job Object,
// then resumed — closing the race window where fast-spawning malware could
// escape containment between CreateProcess and AssignProcessToJobObject.
type WindowsJobProcess struct {
	pid          int
	procHandle   syscall.Handle
	jobHandle    syscall.Handle
	stdoutReader *os.File
	stderrReader *os.File
	// write ends kept open until Wait() so the readers don't get EOF early
	stdoutWriter *os.File
	stderrWriter *os.File
	// waitDone is closed after the process exits
	waitOnce chan struct{}
	exitCode int
}

func (p *WindowsJobProcess) PID() int { return p.pid }

func (p *WindowsJobProcess) Kill() error {
	r1, _, err := procTerminateJobObject.Call(uintptr(p.jobHandle), 1)
	if r1 == 0 {
		return fmt.Errorf("TerminateJobObject: %v", err)
	}
	return nil
}

func (p *WindowsJobProcess) Wait() (int, error) {
	// Block until the primary process exits.
	_, err := syscall.WaitForSingleObject(p.procHandle, syscall.INFINITE)
	if err != nil {
		return -1, fmt.Errorf("WaitForSingleObject: %v", err)
	}

	var code uint32
	if err := syscall.GetExitCodeProcess(p.procHandle, &code); err != nil {
		code = 0
	}

	// Close write ends of pipes so readers reach EOF.
	p.stdoutWriter.Close()
	p.stderrWriter.Close()

	syscall.CloseHandle(p.procHandle)
	procCloseHandleW(p.jobHandle)

	return int(code), nil
}

func (p *WindowsJobProcess) Stdout() io.Reader { return p.stdoutReader }
func (p *WindowsJobProcess) Stderr() io.Reader { return p.stderrReader }

// procCloseHandleW is a thin wrapper so we can call kernel32.CloseHandle
// without importing the full windows package handle type here.
func procCloseHandleW(h syscall.Handle) {
	syscall.CloseHandle(h)
}

// ─── WindowsIsolationProvider ─────────────────────────────────────────────────

type WindowsIsolationProvider struct{}

func NewProvider() *WindowsIsolationProvider {
	return &WindowsIsolationProvider{}
}

// CreateProcess spawns the target binary under a fully configured Job Object.
//
// Race-free sequence:
//  1. Create + configure Job Object with all resource limits
//  2. Call CreateProcessW with CREATE_SUSPENDED — process image is mapped but
//     the primary thread has not executed a single instruction yet
//  3. AssignProcessToJobObject — guaranteed before any user code runs
//  4. ResumeThread — primary thread starts executing inside the job
//
// This eliminates the window between step 2 and 3 where the old code
// (using exec.Cmd + CREATE_NEW_CONSOLE) allowed the process to run freely
// and potentially spawn child processes that escape the Job Object.
func (w *WindowsIsolationProvider) CreateProcess(
	ctx context.Context,
	path string,
	args []string,
	dir string,
	limits Limits,
) (Process, error) {

	// ── Step 1: Create Job Object ─────────────────────────────────────────
	jobH, err := createJobObject()
	if err != nil {
		return nil, err
	}

	if err := applyJobLimits(jobH, limits); err != nil {
		syscall.CloseHandle(jobH)
		return nil, err
	}

	// ── Step 2: Build anonymous pipe pairs for stdout/stderr ──────────────
	stdoutR, stdoutW, err := newInheritablePipe()
	if err != nil {
		syscall.CloseHandle(jobH)
		return nil, fmt.Errorf("stdout pipe: %v", err)
	}
	stderrR, stderrW, err := newInheritablePipe()
	if err != nil {
		stdoutR.Close(); stdoutW.Close()
		syscall.CloseHandle(jobH)
		return nil, fmt.Errorf("stderr pipe: %v", err)
	}

	// ── Step 3: CreateProcessW with CREATE_SUSPENDED ──────────────────────
	//
	// We call CreateProcessW directly instead of exec.Cmd so that:
	//   a) We can pass CREATE_SUSPENDED in dwCreationFlags
	//   b) We get PROCESS_INFORMATION back, which contains hThread — the
	//      primary thread handle needed for ResumeThread
	//
	// exec.Cmd.Start() does not expose hThread and does not support
	// CREATE_SUSPENDED in a way that lets us retrieve the thread handle.

	cmdLine := buildCommandLine(path, args)
	cmdLinePtr, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		stdoutR.Close(); stdoutW.Close()
		stderrR.Close(); stderrW.Close()
		syscall.CloseHandle(jobH)
		return nil, fmt.Errorf("UTF16 cmdline: %v", err)
	}

	var workDirPtr *uint16
	if dir != "" {
		workDirPtr, err = syscall.UTF16PtrFromString(dir)
		if err != nil {
			stdoutR.Close(); stdoutW.Close()
			stderrR.Close(); stderrW.Close()
			syscall.CloseHandle(jobH)
			return nil, fmt.Errorf("UTF16 workdir: %v", err)
		}
	}

	si := startupInfoW{
		Flags:     startfUseStdHandles,
		StdInput:  syscall.Handle(0), // no stdin for sandboxed process
		StdOutput: syscall.Handle(stdoutW.Fd()),
		StdError:  syscall.Handle(stderrW.Fd()),
	}
	si.Cb = uint32(unsafe.Sizeof(si))

	var pi processInformation

	creationFlags := uint32(createSuspended | createNoWindow)

	r1, _, lastErr := procCreateProcessW.Call(
		0,                                      // lpApplicationName (null — use cmdLine)
		uintptr(unsafe.Pointer(cmdLinePtr)),    // lpCommandLine
		0,                                      // lpProcessAttributes
		0,                                      // lpThreadAttributes
		1,                                      // bInheritHandles = TRUE (for pipe handles)
		uintptr(creationFlags),                 // dwCreationFlags
		0,                                      // lpEnvironment (inherit parent)
		uintptr(unsafe.Pointer(workDirPtr)),    // lpCurrentDirectory
		uintptr(unsafe.Pointer(&si)),           // lpStartupInfo
		uintptr(unsafe.Pointer(&pi)),           // lpProcessInformation
	)
	if r1 == 0 {
		stdoutR.Close(); stdoutW.Close()
		stderrR.Close(); stderrW.Close()
		syscall.CloseHandle(jobH)
		return nil, fmt.Errorf("CreateProcessW: %v", lastErr)
	}

	// Close the write ends in the parent — child owns them via inheritance.
	// We keep Go-level *os.File wrappers around the read ends.
	// We also keep the write end Go files alive until Wait() to prevent
	// the pipe from being broken before the process finishes writing.
	// (stdoutW / stderrW are closed inside Wait())

	// ── Step 4: AssignProcessToJobObject — before a single instruction runs ─
	r1, _, lastErr = procAssignProcessToJobObject.Call(
		uintptr(jobH),
		uintptr(pi.Process),
	)
	if r1 == 0 {
		// Assignment failed — terminate the suspended process and clean up.
		syscall.TerminateProcess(pi.Process, 1)
		syscall.CloseHandle(pi.Thread)
		syscall.CloseHandle(pi.Process)
		stdoutR.Close(); stdoutW.Close()
		stderrR.Close(); stderrW.Close()
		syscall.CloseHandle(jobH)
		return nil, fmt.Errorf("AssignProcessToJobObject: %v", lastErr)
	}

	// ── Step 5: ResumeThread — process starts executing inside the job ─────
	ret, _, lastErr := procResumeThread.Call(uintptr(pi.Thread))
	if ret == resumeThreadError {
		syscall.TerminateProcess(pi.Process, 1)
		syscall.CloseHandle(pi.Thread)
		syscall.CloseHandle(pi.Process)
		stdoutR.Close(); stdoutW.Close()
		stderrR.Close(); stderrW.Close()
		syscall.CloseHandle(jobH)
		return nil, fmt.Errorf("ResumeThread: %v", lastErr)
	}

	// Thread handle is no longer needed after resume.
	syscall.CloseHandle(pi.Thread)

	// Honour context cancellation — kill the job if ctx is cancelled.
	go func() {
		<-ctx.Done()
		procTerminateJobObject.Call(uintptr(jobH), 1)
	}()

	return &WindowsJobProcess{
		pid:          int(pi.ProcessID),
		procHandle:   pi.Process,
		jobHandle:    jobH,
		stdoutReader: stdoutR,
		stderrReader: stderrR,
		stdoutWriter: stdoutW,
		stderrWriter: stderrW,
	}, nil
}

// ─── Job Object helpers ───────────────────────────────────────────────────────

func createJobObject() (syscall.Handle, error) {
	r1, _, err := procCreateJobObjectW.Call(0, 0)
	if r1 == 0 {
		return 0, fmt.Errorf("CreateJobObjectW: %v", err)
	}
	return syscall.Handle(r1), nil
}

func applyJobLimits(jobH syscall.Handle, limits Limits) error {
	var ext jobObjectExtendedLimitInfo
	ext.BasicLimitInformation.LimitFlags = jobLimitKillOnJobClose

	if limits.MemoryLimitMB > 0 {
		mem := uintptr(limits.MemoryLimitMB * 1024 * 1024)
		ext.BasicLimitInformation.LimitFlags |= jobLimitJobMemory | jobLimitProcessMemory
		ext.JobMemoryLimit = mem
		ext.ProcessMemoryLimit = mem
	}

	if limits.MaxProcesses > 0 {
		ext.BasicLimitInformation.LimitFlags |= jobLimitActiveProcess
		ext.BasicLimitInformation.ActiveProcessLimit = uint32(limits.MaxProcesses)
	}

	r1, _, err := procSetInformationJobObject.Call(
		uintptr(jobH),
		jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&ext)),
		uintptr(unsafe.Sizeof(ext)),
	)
	if r1 == 0 {
		return fmt.Errorf("SetInformationJobObject (extended limits): %v", err)
	}

	// CPU rate — non-fatal if unsupported (e.g. inside a nested VM without
	// virtualisation extensions for CPU rate control).
	if limits.CPULimitPercent > 0 && limits.CPULimitPercent < 100 {
		cpu := jobObjectCPURateControlInfo{
			ControlFlags: jobCPURateControlEnable | jobCPURateControlHardLimit,
			CpuRate:      uint32(limits.CPULimitPercent * 100), // 25% → 2500
		}
		procSetInformationJobObject.Call(
			uintptr(jobH),
			jobObjectCpuRateControlInformation,
			uintptr(unsafe.Pointer(&cpu)),
			uintptr(unsafe.Sizeof(cpu)),
		)
		// Return value intentionally ignored — CPU limits degrade gracefully.
	}

	return nil
}

// ─── Pipe helpers ─────────────────────────────────────────────────────────────

// newInheritablePipe creates an anonymous pipe where the write end is marked
// inheritable so the child process can use it for stdout/stderr.
// Returns (readEnd, writeEnd, error) as *os.File wrappers.
func newInheritablePipe() (*os.File, *os.File, error) {
	var rHandle, wHandle syscall.Handle

	// Security attributes with bInheritHandle = TRUE for the write end.
	sa := syscall.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		InheritHandle: 1, // both ends inheritable initially
	}

	r1, _, err := procCreatePipe.Call(
		uintptr(unsafe.Pointer(&rHandle)),
		uintptr(unsafe.Pointer(&wHandle)),
		uintptr(unsafe.Pointer(&sa)),
		0, // default buffer size
	)
	if r1 == 0 {
		return nil, nil, fmt.Errorf("CreatePipe: %v", err)
	}

	// Mark the read end as NOT inheritable — the parent keeps it private.
	procSetHandleInformation.Call(
		uintptr(rHandle),
		handleFlagInherit,
		0, // clear HANDLE_FLAG_INHERIT
	)

	r := os.NewFile(uintptr(rHandle), "|r")
	w := os.NewFile(uintptr(wHandle), "|w")
	return r, w, nil
}

// ─── Command line builder ─────────────────────────────────────────────────────

// buildCommandLine constructs a properly quoted Windows command line string
// from an executable path and argument list.
// Each argument that contains spaces is wrapped in double-quotes.
func buildCommandLine(exe string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quoteArg(exe))
	for _, a := range args {
		parts = append(parts, quoteArg(a))
	}
	return strings.Join(parts, " ")
}

// quoteArg wraps an argument in double-quotes if it contains spaces or quotes,
// escaping any embedded double-quote characters.
func quoteArg(s string) string {
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
