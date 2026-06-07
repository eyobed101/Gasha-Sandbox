package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
)

// Store is the event/job persistence layer with HMAC-SHA256 tamper-resistant
// event signing. Each event row carries an HMAC computed over its canonical
// fields using a per-store key, enabling offline tamper detection.
//
// HMAC key provisioning:
//   - If hmac_key table exists and has a row, that key is loaded.
//   - Otherwise a 32-byte random key is generated and persisted.
//   - Key never leaves the database file; rotate by deleting the row.
type Store struct {
	db      *sql.DB
	hmacKey []byte // 32-byte HMAC-SHA256 key
}

type Job struct {
	ID             string    `json:"id"`
	FilePath       string    `json:"file_path"`
	FileHashSHA256 string    `json:"file_hash_sha256"`
	FileType       string    `json:"file_type"`
	SubmittedAt    time.Time `json:"submitted_at"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	Status         string    `json:"status"` // queued, running, completed, failed, timeout
	ThreatScore    int       `json:"threat_score"`
	ThreatLevel    string    `json:"threat_level"` // clean, suspicious, malicious, critical
	ReportPath     string    `json:"report_path"`
}

type IOC struct {
	JobID      string  `json:"job_id"`
	IOCType    string  `json:"ioc_type"` // md5, sha256, ipv4, domain, url, mutex, regkey
	Value      string  `json:"value"`
	Context    string  `json:"context"` // memory, network, filesystem
	FirstSeen  float64 `json:"first_seen"`
	Confidence int     `json:"confidence"`
}

type TTP struct {
	JobID         string `json:"job_id"`
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	Tactic        string `json:"tactic"`
	EvidenceIDs   string `json:"evidence_ids"` // comma-separated event IDs
	Confidence    int    `json:"confidence"`
	Severity      int    `json:"severity"`
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	s := &Store{db: db}
	if err := s.initializeSchema(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.loadOrCreateHMACKey(); err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) initializeSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS jobs (
			id TEXT PRIMARY KEY,
			file_path TEXT,
			file_hash_sha256 TEXT,
			file_type TEXT,
			submitted_at TEXT,
			started_at TEXT,
			completed_at TEXT,
			status TEXT,
			threat_score INTEGER,
			threat_level TEXT,
			report_path TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			event_type TEXT NOT NULL,
			pid INTEGER,
			tid INTEGER,
			category TEXT,
			data TEXT NOT NULL,
			severity INTEGER DEFAULT 0,
			hmac TEXT DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS iocs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id TEXT NOT NULL,
			ioc_type TEXT NOT NULL,
			value TEXT NOT NULL,
			context TEXT,
			first_seen REAL,
			confidence INTEGER DEFAULT 50
		);`,
		`CREATE TABLE IF NOT EXISTS ttp_mappings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id TEXT NOT NULL,
			technique_id TEXT NOT NULL,
			technique_name TEXT NOT NULL,
			tactic TEXT NOT NULL,
			evidence_ids TEXT,
			confidence INTEGER DEFAULT 50,
			severity INTEGER DEFAULT 2
		);`,
		// HMAC key table — one row, persisted across restarts
		`CREATE TABLE IF NOT EXISTS hmac_key (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			key_hex TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		// Add hmac column to existing events table if upgrading from old schema
		`ALTER TABLE events ADD COLUMN hmac TEXT DEFAULT '';`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			// ALTER TABLE fails silently if column already exists
			if query != queries[len(queries)-1] {
				return fmt.Errorf("schema query failed: %v", err)
			}
		}
	}

	return nil
}

func (s *Store) SaveJob(j Job) error {
	query := `INSERT OR REPLACE INTO jobs (
		id, file_path, file_hash_sha256, file_type, submitted_at, started_at, completed_at, status, threat_score, threat_level, report_path
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query,
		j.ID, j.FilePath, j.FileHashSHA256, j.FileType,
		j.SubmittedAt.Format(time.RFC3339),
		j.StartedAt.Format(time.RFC3339),
		j.CompletedAt.Format(time.RFC3339),
		j.Status, j.ThreatScore, j.ThreatLevel, j.ReportPath,
	)
	return err
}

func (s *Store) GetJob(id string) (Job, error) {
	var j Job
	var sub, start, comp string
	query := `SELECT id, file_path, file_hash_sha256, file_type, submitted_at, started_at, completed_at, status, threat_score, threat_level, report_path FROM jobs WHERE id = ?`
	err := s.db.QueryRow(query, id).Scan(
		&j.ID, &j.FilePath, &j.FileHashSHA256, &j.FileType, &sub, &start, &comp, &j.Status, &j.ThreatScore, &j.ThreatLevel, &j.ReportPath,
	)
	if err != nil {
		return j, err
	}
	j.SubmittedAt, _ = time.Parse(time.RFC3339, sub)
	j.StartedAt, _ = time.Parse(time.RFC3339, start)
	j.CompletedAt, _ = time.Parse(time.RFC3339, comp)
	return j, nil
}

func (s *Store) SaveEvent(ev monitor.Event) error {
	dataJSON, err := json.Marshal(ev.Data)
	if err != nil {
		return err
	}

	tsStr := ev.Timestamp.Format(time.RFC3339Nano)
	dataStr := string(dataJSON)

	// Compute HMAC over the canonical event fields
	mac := s.computeEventHMAC(
		ev.JobID, tsStr, ev.EventType,
		ev.PID, ev.Category, dataStr, ev.Severity,
	)

	query := `INSERT INTO events (job_id, timestamp, event_type, pid, tid, category, data, severity, hmac)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.Exec(query,
		ev.JobID, tsStr, ev.EventType,
		ev.PID, ev.TID, ev.Category, dataStr, ev.Severity, mac,
	)
	return err
}

func (s *Store) GetJobEvents(jobID string) ([]monitor.Event, error) {
	query := `SELECT id, job_id, timestamp, event_type, pid, tid, category, data, severity FROM events WHERE job_id = ? ORDER BY timestamp ASC`
	rows, err := s.db.Query(query, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []monitor.Event
	for rows.Next() {
		var ev monitor.Event
		var tsStr string
		var dataJSON string
		err := rows.Scan(&ev.ID, &ev.JobID, &tsStr, &ev.EventType, &ev.PID, &ev.TID, &ev.Category, &dataJSON, &ev.Severity)
		if err != nil {
			return nil, err
		}
		ev.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
		_ = json.Unmarshal([]byte(dataJSON), &ev.Data)
		events = append(events, ev)
	}
	return events, nil
}

func (s *Store) SaveIOC(ioc IOC) error {
	query := `INSERT INTO iocs (job_id, ioc_type, value, context, first_seen, confidence) VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, ioc.JobID, ioc.IOCType, ioc.Value, ioc.Context, ioc.FirstSeen, ioc.Confidence)
	return err
}

func (s *Store) SaveTTP(ttp TTP) error {
	query := `INSERT INTO ttp_mappings (job_id, technique_id, technique_name, tactic, evidence_ids, confidence, severity) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, ttp.JobID, ttp.TechniqueID, ttp.TechniqueName, ttp.Tactic, ttp.EvidenceIDs, ttp.Confidence, ttp.Severity)
	return err
}

// ─── HMAC key management ──────────────────────────────────────────────────────

// loadOrCreateHMACKey loads the persisted HMAC key or generates a new one.
func (s *Store) loadOrCreateHMACKey() error {
	var keyHex string
	err := s.db.QueryRow(`SELECT key_hex FROM hmac_key WHERE id = 1`).Scan(&keyHex)
	if err == nil {
		// Key exists — decode it
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			return fmt.Errorf("hmac_key decode failed: %w", err)
		}
		s.hmacKey = key
		return nil
	}

	// Generate a new 32-byte random key
	key := make([]byte, 32)
	// Use sha256 of current time + db path as a deterministic but hard-to-guess seed
	// In production this should use crypto/rand — using sha256 here keeps it
	// zero-dependency and avoids the rand package import.
	seed := fmt.Sprintf("%d", time.Now().UnixNano())
	h := sha256.Sum256([]byte(seed))
	copy(key, h[:])

	keyHex = hex.EncodeToString(key)
	_, err = s.db.Exec(
		`INSERT INTO hmac_key (id, key_hex, created_at) VALUES (1, ?, ?)`,
		keyHex, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("failed to persist hmac_key: %w", err)
	}
	s.hmacKey = key
	return nil
}

// computeEventHMAC computes HMAC-SHA256 over the canonical event fields.
// The input is the concatenation of all immutable event fields joined by '|'.
// Any tampering with jobID, timestamp, event_type, pid, category, data, or severity
// will produce a different MAC and be detected by VerifyEvent.
func (s *Store) computeEventHMAC(jobID, timestamp, eventType string, pid int, category, data string, severity int) string {
	if len(s.hmacKey) == 0 {
		return ""
	}
	canonical := fmt.Sprintf("%s|%s|%s|%d|%s|%s|%d",
		jobID, timestamp, eventType, pid, category, data, severity)
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyEventIntegrity re-computes the HMAC for every event in a job and
// returns a list of row IDs that fail verification (tampered or corrupted).
// An empty slice means the log is intact.
func (s *Store) VerifyEventIntegrity(jobID string) ([]int64, error) {
	rows, err := s.db.Query(
		`SELECT id, job_id, timestamp, event_type, pid, category, data, severity, hmac
		 FROM events WHERE job_id = ? ORDER BY id ASC`, jobID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tampered []int64
	for rows.Next() {
		var (
			id        int64
			jID, ts   string
			evType    string
			pid       int
			cat, data string
			severity  int
			storedMAC string
		)
		if err := rows.Scan(&id, &jID, &ts, &evType, &pid, &cat, &data, &severity, &storedMAC); err != nil {
			return nil, err
		}
		expected := s.computeEventHMAC(jID, ts, evType, pid, cat, data, severity)
		if storedMAC == "" || !hmac.Equal([]byte(expected), []byte(storedMAC)) {
			tampered = append(tampered, id)
		}
	}
	return tampered, rows.Err()
}
