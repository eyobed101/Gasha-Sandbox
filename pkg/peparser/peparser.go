// Package peparser wraps github.com/saferwall/pe to provide malware-oriented
// static analysis of PE (Portable Executable) files. It replaces the previous
// debug/pe usage in pkg/rules/yara.go with richer, malformation-tolerant parsing.
//
// Features added over stdlib debug/pe:
//   - Structural anomaly detection (overlapping sections, invalid checksum …)
//   - Authenticode certificate chain extraction
//   - TLS callback detection (T1055.005)
//   - Full import/export tables with thunk addresses
//   - Per-section entropy with RWX flag detection
package peparser

import (
	"fmt"

	saferpe "github.com/saferwall/pe"
	"github.com/lemas-sandbox/lemas/pkg/logger"
)

// Hit is a self-contained detection finding returned by Analyze.
// Intentionally decoupled from pkg/rules to avoid an import cycle —
// callers in pkg/rules convert these to rules.RuleHit.
type Hit struct {
	RuleName    string
	Engine      string
	Description string
	Severity    string
	MITRETTP    string
	MatchedOn   string
	Evidence    string
}

// Result contains all malware-relevant findings from a PE analysis.
type Result struct {
	IsPE             bool
	Is64Bit          bool
	Imports          []string          // "DLL!FunctionName" entries
	Exports          []string
	Anomalies        []string
	HasTLSCallbacks  bool
	HasAuthenticode  bool
	SignerName       string
	SectionEntropies map[string]float64
	Hits             []Hit
}

var log = logger.ForComponent("peparser")

// Analyze parses a PE file and returns structured findings.
// Returns a non-nil *Result with IsPE==false when the file is not a PE.
func Analyze(path string) (*Result, error) {
	res := &Result{SectionEntropies: make(map[string]float64)}

	// Options uses Omit* flags (opt-out model); defaults parse everything.
	// Enable per-section entropy explicitly.
	opts := saferpe.Options{
		SectionEntropy: true,
	}

	pe, err := saferpe.New(path, &opts)
	if err != nil {
		return res, nil // not a PE or fatally malformed
	}
	defer pe.Close()

	if err := pe.Parse(); err != nil {
		log.Warn().Str("path", path).Err(err).Msg("PE parse partial — continuing with available data")
	}

	res.IsPE = true
	res.Is64Bit = pe.Is64 // bool field on FileInfo (embedded in File)

	// ── Imports ──────────────────────────────────────────────────────────────
	for _, imp := range pe.Imports {
		for _, fn := range imp.Functions {
			res.Imports = append(res.Imports, imp.Name+"!"+fn.Name)
		}
	}

	// ── Exports ──────────────────────────────────────────────────────────────
	for _, exp := range pe.Export.Functions {
		res.Exports = append(res.Exports, exp.Name)
	}

	// ── TLS Callbacks ────────────────────────────────────────────────────────
	// Callbacks is interface{} — a non-nil value means callbacks exist.
	if pe.HasTLS && pe.TLS.Callbacks != nil {
		res.HasTLSCallbacks = true
		res.Hits = append(res.Hits, Hit{
			RuleName:    "TLSCallbackPresent",
			Engine:      "peparser",
			Description: "PE contains TLS callbacks — common in packers and anti-debug tricks.",
			Severity:    "medium",
			MITRETTP:    "T1055.005",
			MatchedOn:   path,
			Evidence:    "TLS callbacks detected",
		})
	}

	// ── Authenticode ─────────────────────────────────────────────────────────
	if pe.IsSigned && len(pe.Certificates.Certificates) > 0 {
		res.HasAuthenticode = true
		res.SignerName = pe.Certificates.Certificates[0].Info.Subject
	}

	// ── Structural anomalies ─────────────────────────────────────────────────
	for _, a := range pe.Anomalies {
		res.Anomalies = append(res.Anomalies, a)
		res.Hits = append(res.Hits, Hit{
			RuleName:    "PEAnomaly",
			Engine:      "peparser",
			Description: "PE structural anomaly — common in malware abusing loader quirks.",
			Severity:    "medium",
			MITRETTP:    "T1027",
			MatchedOn:   path,
			Evidence:    a,
		})
	}

	// ── Section analysis ─────────────────────────────────────────────────────
	const (
		imageScnMemExecute = uint32(0x20000000)
		imageScnMemWrite   = uint32(0x80000000)
	)
	for _, sec := range pe.Sections {
		// Name is a null-padded [8]uint8 — trim to a clean string.
		raw := sec.Header.Name[:]
		end := len(raw)
		for end > 0 && raw[end-1] == 0 {
			end--
		}
		name := string(raw[:end])
		ent := sec.CalculateEntropy(pe)
		res.SectionEntropies[name] = ent

		chars := sec.Header.Characteristics
		if chars&imageScnMemExecute != 0 && chars&imageScnMemWrite != 0 {
			res.Hits = append(res.Hits, Hit{
				RuleName:    "RWXSectionDetected",
				Engine:      "peparser",
				Description: "PE section is writable and executable — shellcode staging indicator.",
				Severity:    "high",
				MITRETTP:    "T1055",
				MatchedOn:   path,
				Evidence:    fmt.Sprintf("Section %s: flags=0x%08x", name, chars),
			})
		}
		if ent > 7.2 && chars&imageScnMemExecute != 0 {
			res.Hits = append(res.Hits, Hit{
				RuleName:    "HighEntropyExecutableSection",
				Engine:      "peparser",
				Description: "Executable PE section has high entropy — packed or encrypted code.",
				Severity:    "high",
				MITRETTP:    "T1027",
				MatchedOn:   path,
				Evidence:    fmt.Sprintf("Section %s: entropy=%.2f", name, ent),
			})
		}
	}

	// ── Injection API import detection ────────────────────────────────────────
	injectionAPIs := map[string]bool{
		"VirtualAlloc": true, "VirtualAllocEx": true,
		"WriteProcessMemory": true, "CreateRemoteThread": true,
		"NtCreateThreadEx": true, "IsDebuggerPresent": true,
		"CheckRemoteDebuggerPresent": true, "NtDelayExecution": true,
		"OpenProcess": true, "NtOpenProcess": true,
	}
	matched := 0
	for _, imp := range pe.Imports {
		for _, fn := range imp.Functions {
			if injectionAPIs[fn.Name] {
				matched++
			}
		}
	}
	if matched >= 3 {
		res.Hits = append(res.Hits, Hit{
			RuleName:    "ProcessInjectionAPIImports",
			Engine:      "peparser",
			Description: "PE imports multiple APIs used for process hollowing and injection.",
			Severity:    "high",
			MITRETTP:    "T1055",
			MatchedOn:   path,
			Evidence:    fmt.Sprintf("Matched %d injection API imports", matched),
		})
	}

	return res, nil
}
