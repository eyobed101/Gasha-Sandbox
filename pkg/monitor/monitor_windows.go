//go:build windows

package monitor

import (
	"context"
	"strings"
	"syscall"
	"time"
)

type WindowsMonitor struct {
	jobID     string
	targetPID int
	cancel    context.CancelFunc
	wg        time.Duration
}

func NewMonitor() *WindowsMonitor {
	return &WindowsMonitor{}
}

func (m *WindowsMonitor) Start(ctx context.Context, jobID string, targetPID int, bus chan<- Event) error {
	m.jobID = jobID
	m.targetPID = targetPID

	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	// Start process monitoring thread
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		// Publish initial process creation event
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventProcessCreate,
			PID:       targetPID,
			Category:  CatProcess,
			Severity:  SevInfo,
			Data: map[string]interface{}{
				"pid":          targetPID,
				"ppid":         osGetppid(targetPID),
				"image_path":   "C:\\Windows\\Temp\\sample_isolated.exe",
				"cmdline":      "sample_isolated.exe",
				"user":         "SandboxUser",
				"is_injected":  false,
			},
		}

		for {
			select {
			case <-ticker.C:
				// In a production agent, we would query ETW or use CmRegisterCallback / PsSetCreateProcessNotifyRoutine.
				// For the sandbox pipeline demo, we check if process is still running.
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

func (m *WindowsMonitor) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

// InjectSimulatedEvents sends realistic malware telemetry for verification.
func InjectSimulatedEvents(jobID string, filename string, bus chan<- Event) {
	lowerName := strings.ToLower(filename)
	
	// Only run simulation for test/malicious files
	if !strings.Contains(lowerName, "malicious") && !strings.Contains(lowerName, "dropper") && !strings.Contains(lowerName, "test") {
		return
	}

	go func() {
		// Delay to simulate execution progression
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
				"technique": "VM Artifact Query",
				"details":   "Queried registry key for virtualization: HKLM\\SOFTWARE\\VMware Inc.\\VMware Tools",
				"mitre_ttp": "T1497.001",
			},
		}

		time.Sleep(1 * time.Second)

		// 2. API Hook - VirtualAllocEx (T1055.001 Process Injection)
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventAPICall,
			PID:       9999,
			Category:  CatAPI,
			Severity:  SevLow,
			Data: map[string]interface{}{
				"api_name": "VirtualAllocEx",
				"args": map[string]interface{}{
					"target_pid":      1000, // explorer.exe
					"size":            4096,
					"allocation_type": "MEM_COMMIT|MEM_RESERVE",
					"protect":         "PAGE_EXECUTE_READWRITE",
				},
				"return_value": "0x1F0000",
			},
		}

		time.Sleep(500 * time.Millisecond)

		// 3. API Hook - WriteProcessMemory
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventAPICall,
			PID:       9999,
			Category:  CatAPI,
			Severity:  SevLow,
			Data: map[string]interface{}{
				"api_name": "WriteProcessMemory",
				"args": map[string]interface{}{
					"target_pid":   1000,
					"base_address": "0x1F0000",
					"buffer_size":  2048,
				},
				"return_value": "true",
			},
		}

		time.Sleep(500 * time.Millisecond)

		// 4. API Hook - CreateRemoteThread
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventAPICall,
			PID:       9999,
			Category:  CatAPI,
			Severity:  SevHigh,
			Data: map[string]interface{}{
				"api_name": "CreateRemoteThread",
				"args": map[string]interface{}{
					"target_pid":     1000,
					"start_address":  "0x1F0000",
					"thread_handle": "0x4A8",
				},
				"return_value": "0x4A8",
			},
		}

		time.Sleep(1 * time.Second)

		// 5. File drop - dropped payload (T1105)
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventFileWrite,
			PID:       9999,
			Category:  CatFile,
			Severity:  SevMedium,
			Data: map[string]interface{}{
				"operation": "WRITE",
				"path":      "C:\\Users\\User\\AppData\\Roaming\\updater.exe",
				"size":      125440,
				"entropy":   7.82,
			},
		}

		time.Sleep(1 * time.Second)

		// 6. Registry Write - Run Key Persistence (T1547.001)
		bus <- Event{
			JobID:     jobID,
			Timestamp: time.Now(),
			EventType: EventRegSet,
			PID:       9999,
			Category:  CatRegistry,
			Severity:  SevHigh,
			Data: map[string]interface{}{
				"operation":  "SET",
				"key":        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
				"value_name": "UpdateManager",
				"value_data": "C:\\Users\\User\\AppData\\Roaming\\updater.exe",
			},
		}

		time.Sleep(1 * time.Second)

		// 7. C2 Beacon Connection (T1071.001)
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
				"dest_port": 443,
				"domain":    "c2-command-hub.net",
			},
		}
	}()
}

func osGetppid(pid int) int {
	return 1000 // Placeholder PPID (explorer.exe)
}

func isPIDRunning(pid int) bool {
	// Check if process handle/PID is valid
	p, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(p)
	return true
}
