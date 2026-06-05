package monitor_test

import (
	"testing"
	"time"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
)

func TestCorrelationPrivilegeEscalationWindows(t *testing.T) {
	alerts := make(chan monitor.Event, 10)
	ce := monitor.NewCorrelationEngine("test-job", alerts)

	// Spawn parent (medium integrity)
	ce.ProcessEvent(monitor.Event{
		JobID:     "test-job",
		Timestamp: time.Now(),
		EventType: monitor.EventProcessCreate,
		PID:       1000,
		Category:  monitor.CatProcess,
		Data: map[string]interface{}{
			"ppid":            500,
			"image_path":      "C:\\Windows\\explorer.exe",
			"integrity_level": "Medium",
		},
	})

	// Spawn child (High integrity)
	ce.ProcessEvent(monitor.Event{
		JobID:     "test-job",
		Timestamp: time.Now(),
		EventType: monitor.EventProcessCreate,
		PID:       2000,
		Category:  monitor.CatProcess,
		Data: map[string]interface{}{
			"ppid":            1000,
			"image_path":      "C:\\Windows\\Temp\\malicious.exe",
			"integrity_level": "High",
		},
	})

	// Check if alert was generated
	select {
	case alert := <-alerts:
		if alert.Category != monitor.CatEvasion {
			t.Errorf("expected evasion category, got %s", alert.Category)
		}
		ttp := alert.Data["mitre_ttp"].(string)
		if ttp != "T1068" {
			t.Errorf("expected T1068 TTP for privilege escalation, got %s", ttp)
		}
	default:
		t.Fatal("expected privilege escalation alert, but none was sent")
	}
}

func TestCorrelationProcessInjection(t *testing.T) {
	alerts := make(chan monitor.Event, 10)
	ce := monitor.NewCorrelationEngine("test-job", alerts)

	// API call: VirtualAllocEx from PID 1000 to target PID 2000
	ce.ProcessEvent(monitor.Event{
		JobID:     "test-job",
		Timestamp: time.Now(),
		EventType: monitor.EventAPICall,
		PID:       1000,
		Category:  monitor.CatAPI,
		Data: map[string]interface{}{
			"api_name":   "VirtualAllocEx",
			"target_pid": 2000,
		},
	})

	// API call: WriteProcessMemory
	ce.ProcessEvent(monitor.Event{
		JobID:     "test-job",
		Timestamp: time.Now(),
		EventType: monitor.EventAPICall,
		PID:       1000,
		Category:  monitor.CatAPI,
		Data: map[string]interface{}{
			"api_name":   "WriteProcessMemory",
			"target_pid": 2000,
		},
	})

	// API call: CreateRemoteThread -> Should trigger critical injection alert
	ce.ProcessEvent(monitor.Event{
		JobID:     "test-job",
		Timestamp: time.Now(),
		EventType: monitor.EventAPICall,
		PID:       1000,
		Category:  monitor.CatAPI,
		Data: map[string]interface{}{
			"api_name":   "CreateRemoteThread",
			"target_pid": 2000,
		},
	})

	// Check alerts
	foundInjectionAlert := false
	close(alerts)
	for alert := range alerts {
		if alert.Data["mitre_ttp"] == "T1055.001" {
			foundInjectionAlert = true
		}
	}

	if !foundInjectionAlert {
		t.Fatal("expected critical process injection alert (T1055.001)")
	}
}

func TestCorrelationPersistenceToC2(t *testing.T) {
	alerts := make(chan monitor.Event, 10)
	ce := monitor.NewCorrelationEngine("test-job", alerts)

	// Write to registry run key
	ce.ProcessEvent(monitor.Event{
		JobID:     "test-job",
		Timestamp: time.Now(),
		EventType: monitor.EventRegSet,
		PID:       3000,
		Category:  monitor.CatRegistry,
		Data: map[string]interface{}{
			"key":        `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			"value_name": "Backdoor",
		},
	})

	// Network connection from same PID
	ce.ProcessEvent(monitor.Event{
		JobID:     "test-job",
		Timestamp: time.Now(),
		EventType: monitor.EventNetConnect,
		PID:       3000,
		Category:  monitor.CatNetwork,
		Data: map[string]interface{}{
			"dest_ip":   "192.168.1.100",
			"dest_port": 443,
		},
	})

	select {
	case alert := <-alerts:
		ttp := alert.Data["mitre_ttp"].(string)
		if ttp != "T1071.001" {
			t.Errorf("expected T1071.001 (C2 Beaconing from persistent process), got %s", ttp)
		}
	default:
		t.Fatal("expected C2 persistence correlation alert")
	}
}
