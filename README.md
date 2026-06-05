# LEMAS — Lightweight Endpoint Malware Analysis Sandbox

> **Production-grade behavioral sandbox in Go.** CAPEv2-level intelligence in a sub-200 MB agent — no dedicated VM infrastructure required.

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](#license)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?style=flat)](#)

---

## Overview

LEMAS is a **self-contained malware analysis agent** written in Go. It dynamically executes suspicious files inside an OS-native isolation envelope (Windows Job Objects / Linux Namespaces), collects rich behavioral telemetry from process, file system, registry, network, and API layers, correlates events against YARA and Sigma-style rules, maps detections to **MITRE ATT&CK**, and outputs structured JSON + interactive HTML reports.

It integrates into any antimalware or EDR stack via:

- A **CLI binary** for analyst workstations and air-gapped environments
- A **REST API daemon** for SOAR/webhook-driven pipelines
- A **C-shared library** (`lemas.dll` / `lemas.so`) for in-process EDR embedding

---

## Key Features

| Capability | Detail |
|---|---|
| **OS-native isolation** | Windows Job Objects (CPU%, RAM, MaxProc) · Linux Namespaces (PID/NET/UTS/IPC) |
| **Process monitoring** | Full process tree lifecycle, parent-child anomaly detection |
| **API hook telemetry** | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, RegSetValueEx, and 40+ more |
| **File & registry tracking** | Create/write/delete/rename ops · startup dir & Run key persistence detection |
| **Network analysis** | C2 IP/domain extraction · DNS query logging · beacon pattern detection |
| **Memory scanning** | MZ header in unbacked pages · high-entropy shellcode · Mimikatz signatures |
| **Anti-analysis detection** | VM artifact queries · debugger checks · sleep/timing evasion — all mapped to T1497 |
| **YARA engine** | Pure-Go (no CGO): PE parser, Shannon entropy, byte-pattern signatures |
| **Sigma correlator** | Behavioral event chains → MITRE ATT&CK technique identification |
| **Threat scoring** | Weighted 0–100 score → CLEAN / SUSPICIOUS / MALICIOUS / CRITICAL |
| **Reports** | Structured JSON + interactive glassmorphic HTML dashboard |
| **EDR integration** | REST API · C-shared library (`LemasInit`/`LemasSubmit`/`LemasClose`) |
| **Zero CGO** | Pure-Go SQLite (`modernc.org/sqlite`) — single binary, no runtime DLLs |

---

## Architecture

```
                        ┌─────────────────────────────────────┐
                        │         SUBMISSION INTERFACE         │
                        │   CLI  ·  REST API  ·  C-Library    │
                        └──────────────┬──────────────────────┘
                                       │
                        ┌──────────────▼──────────────────────┐
                        │      SANDBOX ORCHESTRATOR            │
                        │  Job Queue · Policy Engine · Timer  │
                        └──────────────┬──────────────────────┘
                                       │
              ┌────────────────────────▼───────────────────────┐
              │                 ISOLATION LAYER                  │
              │  Windows: Job Objects · AppContainer            │
              │  Linux:   Namespaces (PID/NET/UTS/IPC/MNT)     │
              └────────────────────────┬───────────────────────┘
                                       │
              ┌────────────────────────▼───────────────────────┐
              │           INSTRUMENTATION BUS (lock-free)       │
              └──┬───────────┬──────────┬──────────┬──────────┘
                 │           │          │          │
           Process      File/Reg    Network     API Hook
           Monitor      Tracker     Capture     Engine
                 │           │          │          │
              ┌──▼───────────▼──────────▼──────────▼──────────┐
              │           RULE ENGINE LAYER                     │
              │    YARA Scanner  ·  Sigma Correlator           │
              └──────────────────┬─────────────────────────────┘
                                 │
              ┌──────────────────▼─────────────────────────────┐
              │     MITRE ATT&CK Mapper · Threat Scorer        │
              └──────────────────┬─────────────────────────────┘
                                 │
              ┌──────────────────▼─────────────────────────────┐
              │       REPORT GENERATOR (JSON + HTML)            │
              └────────────────────────────────────────────────┘
```

---

## Project Structure

```
.
├── cmd/
│   ├── lemas/          # CLI entry point
│   └── lemas-c/        # C-shared library exporter
├── pkg/
│   ├── isolation/      # Windows Job Objects & Linux Namespace providers
│   ├── monitor/        # Event schemas, Instrumentation Bus, OS harvesters
│   ├── rules/          # YARA scanner, Sigma behavioral correlator
│   ├── storage/        # Pure-Go SQLite event/job/IOC/TTP store
│   ├── report/         # JSON + HTML report generator
│   ├── orchestrator/   # Job queue, policy engine, lifecycle manager
│   └── integration/    # HTTP REST API server
├── go.mod
├── config.yaml         # Runtime configuration
└── README.md
```

---

## Quick Start

### Prerequisites

- **Go 1.21+** — [download](https://go.dev/dl/)
- Windows 10/11 or Linux (kernel ≥ 5.x for namespace support)
- No other runtime dependencies

### Build

```bash
git clone https://github.com/lemas-sandbox/lemas
cd lemas
go mod tidy
go build -o lemas.exe ./cmd/lemas/     # Windows
go build -o lemas     ./cmd/lemas/     # Linux
```

### Standalone Analysis

```bash
# Analyze a file and get a threat report
./lemas -file /path/to/suspicious.exe -db lemas.db -reports ./reports -rules ./rules
```

**Example output:**
```
[+] Submitting target file: /path/to/suspicious.exe
[+] Analysis job queued. ID: b9769ab7-17f3-b262-ca04-09269130640a
[*] Executing analysis... (max timeout: 120s)
[+] Analysis complete!

=========================================
           ANALYSIS RUN SUMMARY
=========================================
THREAT CLASSIFICATION : MALICIOUS
THREAT SCORE (0-100)  : 87
BEHAVIOR SUMMARY      : Critical security alert. Sample demonstrated
                        process injection, Run key persistence, and
                        encrypted C2 communication.
KEY DETECTED BEHAVIORS:
 - Process injection via CreateRemoteThread (T1055.001)
 - Registry Run key persistence (T1547.001)
 - C2 network beacon to 185.220.101.5:443 (T1071.001)
 - VM/sandbox evasion attempt (T1497.001)
=========================================
Full HTML Report: reports/b9769ab7-.../report.html
```

### REST API Daemon

```bash
./lemas -daemon -addr :8080 -db lemas.db -reports ./reports -rules ./rules
```

| Endpoint | Method | Description |
|---|---|---|
| `/submit` | `POST` | Upload file (`multipart/form-data`) or `?path=` local path |
| `/status/{job-id}` | `GET` | `{"job_id":"...","status":"running\|completed"}` |
| `/report/{job-id}/json` | `GET` | Full structured JSON report |
| `/report/{job-id}/html` | `GET` | Interactive HTML dashboard |

```bash
# Submit via curl
curl -X POST http://localhost:8080/submit \
  -F "file=@suspicious.exe"

# Check status
curl http://localhost:8080/status/b9769ab7-17f3-b262-ca04-09269130640a

# Fetch JSON report
curl http://localhost:8080/report/b9769ab7-17f3-b262-ca04-09269130640a/json
```

### EDR / C-Shared Library

Build the shared library:

```bash
# Windows
go build -buildmode=c-shared -o lemas.dll ./cmd/lemas-c/

# Linux
go build -buildmode=c-shared -o lemas.so ./cmd/lemas-c/
```

Call from C/C++, Rust, Python, or any FFI-capable language:

```c
#include "lemas.h"

// Initialize the engine once at EDR startup
if (!LemasInit("./lemas.db", "./reports", "./rules")) {
    fprintf(stderr, "LEMAS init failed\n");
    return 1;
}

// Submit a quarantined file for analysis
char* jobID = LemasSubmit("C:\\quarantine\\sample_a1b2c3.exe");
if (jobID) {
    printf("Analysis started: %s\n", jobID);
    free(jobID);
}

// Shut down cleanly
LemasClose();
```

---

## Configuration

Edit `config.yaml` to tune the agent:

```yaml
analysis:
  default_timeout_seconds: 120   # Hard kill timeout
  storage_path: "./lemas.db"
  reports_dir: "./reports"
  rules_dir: "./rules"

isolation:
  provider: "job_object"          # job_object (Windows) | namespace (Linux)
  cpu_limit_percent: 25
  memory_limit_mb: 200
  max_processes: 10

network:
  containment: "loopback_only"    # deny_all | loopback_only | monitored_egress
  pcap_enabled: true

rules:
  yara:
    enabled: true
    fast_scan: true
  sigma:
    enabled: true
    batch_window_ms: 100
```

---

## MITRE ATT&CK Coverage

| Detection | Technique | Tactic |
|---|---|---|
| CreateRemoteThread injection | T1055.001 | Defense Evasion |
| PE in non-backed memory | T1055.002 | Defense Evasion |
| Process hollowing | T1055.012 | Defense Evasion |
| Registry Run key write | T1547.001 | Persistence |
| Windows Service creation | T1543.003 | Persistence |
| Scheduled Task API | T1053.005 | Execution |
| LSASS memory read | T1003.001 | Credential Access |
| C2 beaconing | T1071.001 | Command & Control |
| DGA domain connections | T1568.002 | C2 |
| DNS tunneling | T1071.004 | C2 |
| PowerShell encoded command | T1059.001 | Execution |
| Debugger detection API | T1497.001 | Defense Evasion |
| Sleep/timing evasion | T1497.003 | Defense Evasion |
| VM artifact queries | T1497.001 | Defense Evasion |
| High-entropy packed PE | T1027 | Defense Evasion |
| Reflective code loading | T1620 | Defense Evasion |

---

## Report Output

### JSON Schema

```json
{
  "schema_version": "1.0",
  "job_id": "b9769ab7-17f3-b262-ca04-09269130640a",
  "analysis_metadata": { "duration_seconds": 7, "os_platform": "windows" },
  "summary": {
    "threat_level": "MALICIOUS",
    "threat_score": 87,
    "behavioral_summary": "...",
    "key_behaviors": ["Process injection via CreateRemoteThread", "..."]
  },
  "mitre_attack": [
    { "technique_id": "T1055.001", "tactic": "Defense Evasion", "confidence": 85 }
  ],
  "iocs": {
    "hashes": { "sha256": "..." },
    "extracted_iocs": [
      { "ioc_type": "ipv4",   "value": "185.220.101.5", "confidence": 90 },
      { "ioc_type": "domain", "value": "c2-hub.net",    "confidence": 90 }
    ]
  },
  "behavioral_timeline": [ ... ],
  "rule_hits": [ ... ]
}
```

### HTML Dashboard

The HTML report is a fully self-contained, single-file interactive dashboard featuring:
- Animated **threat score gauge** with dynamic color theming (green → orange → red)
- **Execution timeline** with per-event severity indicators
- **MITRE ATT&CK grid** mapping detections to tactics and techniques
- **IOC table** with type, value, context, and confidence
- **Signature hits** panel (YARA + Sigma matches with evidence)

---

## Running Tests

```bash
go test -v ./pkg/rules/...    # YARA scanner + entropy tests
go test -v ./pkg/storage/...  # SQLite job/event/IOC/TTP persistence
go test -v ./...               # Full suite
```

---

## Memory & Performance Budget

| Component | RAM |
|---|---|
| Core agent | ~15 MB |
| YARA rule cache | ~30 MB |
| SQLite event store | ~20 MB (flush at 10 MB) |
| Network capture buffer | ~10 MB (ring buffer) |
| Sigma engine | ~20 MB |
| OS overhead | ~30 MB |
| **Total** | **~125 MB** ✅ |

---

## Threat Model

| Threat | Mitigation |
|---|---|
| Malware modifying host filesystem | Isolation layer restricts all writes outside analysis dir |
| Malware C2 egress | Network namespace / loopback-only by default |
| Fork bombs / resource exhaustion | Job Object MaxProcesses + CPU% + RAM hard limits |
| Sleep-based evasion | Analysis timeout hard-kills at configurable deadline |
| Sandbox detection | All evasion attempts **logged** — detection becomes a signal |
| Tampered logs | Append-only SQLite WAL; optional HMAC-signed entries |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

Inspired by [CAPEv2](https://github.com/kevoreilly/CAPEv2), [Cuckoo Sandbox](https://github.com/cuckoosandbox/cuckoo), and the [MITRE ATT&CK](https://attack.mitre.org/) framework. Built with [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) for CGO-free database access.
