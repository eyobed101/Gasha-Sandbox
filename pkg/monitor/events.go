package monitor

import "time"

// Event types
const (
	EventProcessCreate = "process_create"
	EventProcessExit   = "process_exit"
	EventFileWrite     = "file_write"
	EventFileDelete    = "file_delete"
	EventRegSet        = "registry_set"
	EventRegDelete     = "registry_delete"
	EventNetConnect    = "network_connect"
	EventNetDNS        = "network_dns"
	EventAPICall       = "api_call"
	EventEvasion       = "evasion_attempt"
)

// Categories
const (
	CatProcess  = "process"
	CatFile     = "filesystem"
	CatRegistry = "registry"
	CatNetwork  = "network"
	CatAPI      = "api"
	CatEvasion  = "evasion"
)

// Severities
const (
	SevInfo     = 0
	SevLow      = 1
	SevMedium   = 2
	SevHigh     = 3
	SevCritical = 4
)

// Event represents a normalized telemetry report entry.
type Event struct {
	ID        int64                  `json:"id,omitempty"`
	JobID     string                 `json:"job_id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	PID       int                    `json:"pid"`
	TID       int                    `json:"tid,omitempty"`
	Category  string                 `json:"category"`
	Data      map[string]interface{} `json:"data"` // Holds sub-event specific fields
	Severity  int                    `json:"severity"`
}

// ProcessEvent holds process creation and lifecycle data
type ProcessEvent struct {
	PID            int               `json:"pid"`
	PPID           int               `json:"ppid"`
	ImagePath      string            `json:"image_path"`
	CommandLine    string            `json:"cmdline"`
	IntegrityLevel string            `json:"integrity_level,omitempty"`
	User           string            `json:"user,omitempty"`
	ParentImage    string            `json:"parent_image,omitempty"`
	Hashes         map[string]string `json:"hashes,omitempty"`
	IsInjected     bool              `json:"is_injected"`
	IsHollow       bool              `json:"is_hollow"`
}

// FileEvent holds filesystem operation records
type FileEvent struct {
	Operation string `json:"operation"` // WRITE, DELETE, RENAME
	Path      string `json:"path"`
	NewPath   string `json:"new_path,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Entropy   float64`json:"entropy,omitempty"`
}

// RegistryEvent holds registry operations
type RegistryEvent struct {
	Operation string      `json:"operation"` // SET, DELETE
	Key       string      `json:"key"`
	ValueName string      `json:"value_name"`
	ValueData interface{} `json:"value_data,omitempty"`
}

// NetworkEvent holds DNS and connection telemetry
type NetworkEvent struct {
	Protocol string `json:"protocol"` // TCP, UDP, DNS
	DestIP   string `json:"dest_ip,omitempty"`
	DestPort int    `json:"dest_port,omitempty"`
	Domain   string `json:"domain,omitempty"`
	DnsQuery string `json:"dns_query,omitempty"`
	Length   int    `json:"length,omitempty"`
}

// APIEvent holds hook telemetry
type APIEvent struct {
	APIName     string                 `json:"api_name"`
	Args        map[string]interface{} `json:"args"`
	ReturnValue string                 `json:"return_value,omitempty"`
	CallStack   []string               `json:"call_stack,omitempty"`
}

// EvasionEvent holds sandbox detection alerts
type EvasionEvent struct {
	Technique string `json:"technique"` // Timing Evasion, VM Artifact Query, etc.
	Details   string `json:"details"`
	MitreTTP  string `json:"mitre_ttp"`
}
