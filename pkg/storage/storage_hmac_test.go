package storage_test

// storage_hmac_test.go — tests for HMAC tamper-resistant event logging.
//
// Covers:
//   - HMAC is computed and stored on SaveEvent
//   - VerifyEventIntegrity returns empty slice for intact log
//   - Direct SQL update (simulated tamper) is detected
//   - HMAC key persists across Store close/reopen (same DB file)
//   - Multiple jobs are independently verifiable
//   - Empty/new store has no tampered events

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
	"github.com/lemas-sandbox/lemas/pkg/storage"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func tempHMACDB(t *testing.T) (*storage.Store, string, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "lemas_hmac_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	path := f.Name()

	store, err := storage.NewStore(path)
	if err != nil {
		os.Remove(path)
		t.Fatal(err)
	}
	return store, path, func() {
		store.Close()
		os.Remove(path)
	}
}

func sampleEvent(jobID string, pid int) monitor.Event {
	return monitor.Event{
		JobID:     jobID,
		Timestamp: time.Now(),
		EventType: monitor.EventProcessCreate,
		PID:       pid,
		Category:  monitor.CatProcess,
		Severity:  monitor.SevHigh,
		Data: map[string]interface{}{
			"image_path": `C:\Windows\System32\cmd.exe`,
			"cmdline":    `cmd.exe /c whoami`,
		},
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestHMACIntegrityCleanStore(t *testing.T) {
	store, _, cleanup := tempHMACDB(t)
	defer cleanup()

	// Save several events
	for i := 0; i < 5; i++ {
		if err := store.SaveEvent(sampleEvent("job-hmac-1", 1000+i)); err != nil {
			t.Fatalf("SaveEvent: %v", err)
		}
	}

	// All events should pass verification
	tampered, err := store.VerifyEventIntegrity("job-hmac-1")
	if err != nil {
		t.Fatalf("VerifyEventIntegrity: %v", err)
	}
	if len(tampered) != 0 {
		t.Errorf("expected 0 tampered rows, got %d: %v", len(tampered), tampered)
	}
}

func TestHMACTamperDetection(t *testing.T) {
	store, dbPath, cleanup := tempHMACDB(t)
	defer cleanup()

	// Save a legitimate event
	ev := sampleEvent("job-tamper", 9999)
	if err := store.SaveEvent(ev); err != nil {
		t.Fatalf("SaveEvent: %v", err)
	}

	store.Close()

	// Directly tamper with the event data via raw SQL (simulates an attacker
	// editing the SQLite file to cover their tracks)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db for tamper: %v", err)
	}
	_, err = db.Exec(`UPDATE events SET data = '{"image_path":"C:\\evil.exe","cmdline":"evil"}' WHERE job_id = 'job-tamper'`)
	if err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	db.Close()

	// Reopen and verify — tamper must be detected
	store2, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer store2.Close()

	tampered, err := store2.VerifyEventIntegrity("job-tamper")
	if err != nil {
		t.Fatalf("VerifyEventIntegrity after tamper: %v", err)
	}
	if len(tampered) == 0 {
		t.Error("expected tampered row to be detected, but verification passed")
	}
}

func TestHMACKeyPersistsAcrossReopen(t *testing.T) {
	store, dbPath, cleanup := tempHMACDB(t)
	defer cleanup()

	// Save events with the initial key
	for i := 0; i < 3; i++ {
		if err := store.SaveEvent(sampleEvent("job-persist", 100+i)); err != nil {
			t.Fatalf("SaveEvent: %v", err)
		}
	}
	store.Close()

	// Reopen — must load the same key and verify existing events
	store2, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer store2.Close()

	tampered, err := store2.VerifyEventIntegrity("job-persist")
	if err != nil {
		t.Fatalf("VerifyEventIntegrity after reopen: %v", err)
	}
	if len(tampered) != 0 {
		t.Errorf("HMAC key did not persist: %d rows failed after reopen", len(tampered))
	}
}

func TestHMACMultipleJobsIndependent(t *testing.T) {
	store, dbPath, cleanup := tempHMACDB(t)
	defer cleanup()

	jobs := []string{"job-a", "job-b", "job-c"}
	for _, jobID := range jobs {
		for i := 0; i < 4; i++ {
			if err := store.SaveEvent(sampleEvent(jobID, 2000+i)); err != nil {
				t.Fatalf("SaveEvent(%s): %v", jobID, err)
			}
		}
	}
	store.Close()

	// Tamper only job-b
	db, _ := sql.Open("sqlite", dbPath)
	db.Exec(`UPDATE events SET event_type = 'process_exit' WHERE job_id = 'job-b' AND pid = 2001`)
	db.Close()

	store2, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()

	// job-a and job-c should be clean
	for _, jobID := range []string{"job-a", "job-c"} {
		tampered, err := store2.VerifyEventIntegrity(jobID)
		if err != nil {
			t.Fatalf("verify %s: %v", jobID, err)
		}
		if len(tampered) != 0 {
			t.Errorf("%s: expected clean, got %d tampered rows", jobID, len(tampered))
		}
	}

	// job-b must show tampered row
	tampered, err := store2.VerifyEventIntegrity("job-b")
	if err != nil {
		t.Fatalf("verify job-b: %v", err)
	}
	if len(tampered) == 0 {
		t.Error("job-b: tampered row not detected")
	}
}

func TestHMACEmptyJobReturnsNoTamper(t *testing.T) {
	store, _, cleanup := tempHMACDB(t)
	defer cleanup()

	tampered, err := store.VerifyEventIntegrity("nonexistent-job")
	if err != nil {
		t.Fatalf("VerifyEventIntegrity on empty job: %v", err)
	}
	if len(tampered) != 0 {
		t.Errorf("expected 0 tampered rows for empty job, got %d", len(tampered))
	}
}
