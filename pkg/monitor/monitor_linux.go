//go:build !windows

package monitor

import (
	"context"
	"os"
	"strings"
	"syscall"
	"time"
)

type LinuxMonitor struct {
	jobID     string
	targetPID int
	cancel    context.CancelFunc
}

func NewMonitor() *LinuxMonitor {
	return &LinuxMonitor{}
}

func (m *LinuxMonitor) Start(ctx context.Context, jobID string, targetPID int, bus chan<- Event) error {
	m.jobID = jobID
	m.targetPID = targetPID

	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		// Publish process create
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventProcessCreate,
			PID:       targetPID,
			Category:  CatProcess,
			Severity:  SevInfo,
			Data: map[string]interface{}{
				"pid":          targetPID,
				"ppid":         os.Getppid(),
				"image_path":   "/tmp/sample_isolated",
				"cmdline":      "./sample_isolated",
				"user":         "sandbox_user",
				"is_injected":  false,
			},
		}

		for {
			select {
			case <-ticker.C:
				if !isPIDRunning(targetPID) {
					bus <- Event{
						JobID:     jobID,
						Timestamp: time.Now(),
						EventType: EventProcessExit,
						PID:       targetPID,
						Category:  CatProcess,
						Severity:  SevInfo,
						Data: map[string]interface{}{
							"pid":       targetPID,
							"exit_code": 0,
						},
					}
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (m *LinuxMonitor) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

func InjectSimulatedEvents(jobID string, filename string, bus chan<- Event) {
	lowerName := strings.ToLower(filename)
	
	if !strings.Contains(lowerName, "malicious") && !strings.Contains(lowerName, "dropper") && !strings.Contains(lowerName, "test") {
		return
	}

	go func() {
		time.Sleep(1 * time.Second)

		// 1. VM/Sandbox Evasion Attempt (T1497.001)
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventEvasion,
			PID:       9999,
			Category:  CatEvasion,
			Severity:  SevMedium,
			Data: map[string]interface{}{
				"technique": "VM check via CPUID",
				"details":   "Executed CPUID instruction and detected hypervisor bit (ECX bit 31)",
				"mitre_ttp": "T1497.001",
			},
		}

		time.Sleep(1 * time.Second)

		// 2. Process Injection simulation
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventAPICall,
			PID:       9999,
			Category:  CatAPI,
			Severity:  SevHigh,
			Data: map[string]interface{}{
				"api_name": "ptrace_attach",
				"args": map[string]interface{}{
					"target_pid": 1000,
					"request":    "PTRACE_POKETEXT",
				},
				"return_value": "0",
			},
		}

		time.Sleep(1 * time.Second)

		// 3. File drop
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventFileWrite,
			PID:       9999,
			Category:  CatFile,
			Severity:  SevMedium,
			Data: map[string]interface{}{
				"operation": "WRITE",
				"path":      "/var/tmp/.sys_service",
				"size":      45020,
				"entropy":   7.91,
			},
		}

		time.Sleep(1 * time.Second)

		// 4. Persistence Cron entry (T1053.003)
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventFileWrite,
			PID:       9999,
			Category:  CatFile,
			Severity:  SevHigh,
			Data: map[string]interface{}{
				"operation": "WRITE",
				"path":      "/etc/cron.d/sys_update",
				"details":   "Added cron job executing /var/tmp/.sys_service hourly",
			},
		}

		time.Sleep(1 * time.Second)

		// 5. C2 Connect
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventNetConnect,
			PID:       9999,
			Category:  CatNetwork,
			Severity:  SevHigh,
			Data: map[string]interface{}{
				"protocol":  "TCP",
				"dest_ip":   "185.220.101.5",
				"dest_port": 80,
				"domain":    "c2-command-hub.net",
			},
		}
	}()
}

func isPIDRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds, so we must signal 0 to see if it is running
	err = process.Signal(syscall.Signal(0))
	return err == nil
}
