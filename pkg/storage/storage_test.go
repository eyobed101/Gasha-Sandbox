package storage_test

import (
	"os"
	"testing"
	"time"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
	"github.com/lemas-sandbox/lemas/pkg/storage"
)

func tempDB(t *testing.T) (*storage.Store, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "lemas_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	store, err := storage.NewStore(f.Name())
	if err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}

	return store, func() {
		store.Close()
		os.Remove(f.Name())
	}
}

func TestSaveAndGetJob(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	job := storage.Job{
		ID:             "test-job-001",
		FilePath:       "C:\\test\\sample.exe",
		FileHashSHA256: "deadbeef",
		FileType:       "PE32 Executable",
		SubmittedAt:    time.Now(),
		StartedAt:      time.Now(),
		CompletedAt:    time.Now(),
		Status:         "completed",
		ThreatScore:    75,
		ThreatLevel:    "MALICIOUS",
		ReportPath:     "reports/test-job-001/report.html",
	}

	if err := store.SaveJob(job); err != nil {
		t.Fatalf("SaveJob failed: %v", err)
	}

	got, err := store.GetJob("test-job-001")
	if err != nil {
		t.Fatalf("GetJob failed: %v", err)
	}

	if got.ID != job.ID {
		t.Errorf("expected ID %q, got %q", job.ID, got.ID)
	}
	if got.ThreatScore != 75 {
		t.Errorf("expected ThreatScore 75, got %d", got.ThreatScore)
	}
	if got.ThreatLevel != "MALICIOUS" {
		t.Errorf("expected ThreatLevel MALICIOUS, got %q", got.ThreatLevel)
	}
}

func TestSaveAndGetEvents(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	ev := monitor.Event{
		JobID:     "test-job-002",
		Timestamp: time.Now(),
		EventType: monitor.EventProcessCreate,
		PID:       1234,
		Category:  monitor.CatProcess,
		Severity:  monitor.SevHigh,
		Data: map[string]interface{}{
			"image_path": "C:\\malware.exe",
			"cmdline":    "malware.exe -silent",
		},
	}

	if err := store.SaveEvent(ev); err != nil {
		t.Fatalf("SaveEvent failed: %v", err)
	}

	events, err := store.GetJobEvents("test-job-002")
	if err != nil {
		t.Fatalf("GetJobEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventType != monitor.EventProcessCreate {
		t.Errorf("expected event_type %q, got %q", monitor.EventProcessCreate, events[0].EventType)
	}
}

func TestSaveIOC(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	ioc := storage.IOC{
		JobID:      "test-job-003",
		IOCType:    "ipv4",
		Value:      "185.220.101.5",
		Context:    "network",
		Confidence: 90,
	}

	if err := store.SaveIOC(ioc); err != nil {
		t.Fatalf("SaveIOC failed: %v", err)
	}
}

func TestSaveTTP(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	ttp := storage.TTP{
		JobID:         "test-job-004",
		TechniqueID:   "T1055.001",
		TechniqueName: "DLL Injection",
		Tactic:        "Defense Evasion",
		EvidenceIDs:   "1,2,3",
		Confidence:    90,
		Severity:      3,
	}

	if err := store.SaveTTP(ttp); err != nil {
		t.Fatalf("SaveTTP failed: %v", err)
	}
}
