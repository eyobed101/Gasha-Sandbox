//go:build windows

package monitor

import (
	"context"
	"fmt"
	"math/rand"
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
	session       *etw.RealTimeSession
	consumer      *etw.Consumer
	correlator    *CorrelationEngine
}

func NewMonitor() *WindowsMonitor {
	return &WindowsMonitor{
		monitoredPIDs: make(map[int]bool),
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
	providers := []string{
		"Microsoft-Windows-Kernel-Process",
		"Microsoft-Windows-Kernel-File",
		"Microsoft-Windows-Kernel-Registry",
		"Microsoft-Windows-Kernel-Network",
	}

	for _, provName := range providers {
		prov, err := etw.ParseProvider(provName)
		if err != nil {
			s.Stop()
			return fmt.Errorf("failed to parse ETW provider %s: %v", provName, err)
		}
		if err := s.EnableProvider(prov); err != nil {
			s.Stop()
			return fmt.Errorf("failed to enable ETW provider %s: %v. Ensure running as Administrator", provName, err)
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
			user, _ := getPropertyString(e, "UserSid") // System Sid or User String representation

			normalized.Data["pid"] = eventPID
			normalized.Data["ppid"] = ppid
			normalized.Data["image_path"] = image
			normalized.Data["cmdline"] = cmdline
			normalized.Data["user"] = user
			normalized.Data["is_injected"] = false
		} else if e.System.EventID == 2 {
			normalized.EventType = EventProcessExit
			exitCode, _ := getPropertyInt(e, "ExitStatus")
			normalized.Data["pid"] = eventPID
			normalized.Data["exit_code"] = exitCode
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
		} else if strings.Contains(opcodeName, "delete") || strings.Contains(opcodeName, "cleanup") || e.System.EventID == 15 {
			normalized.EventType = EventFileDelete
			normalized.Data["operation"] = "DELETE"
			normalized.Data["path"] = fileName
		} else if strings.Contains(opcodeName, "rename") || e.System.EventID == 16 {
			normalized.EventType = EventFileWrite
			normalized.Data["operation"] = "RENAME"
			normalized.Data["path"] = fileName
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
			if valData, ok := e.EventData["ValueData"]; ok {
				normalized.Data["value_data"] = fmt.Sprintf("%v", valData)
			}
		} else if strings.Contains(opcodeName, "deletevalue") || e.System.EventID == 7 {
			normalized.EventType = EventRegDelete
			normalized.Data["operation"] = "DELETE"
			normalized.Data["key"] = keyName
			valName, _ := getPropertyString(e, "ValueName")
			normalized.Data["value_name"] = valName
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
		if domain, ok := getPropertyString(e, "Domain"); ok {
			normalized.Data["domain"] = domain
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
