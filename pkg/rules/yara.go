package rules

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/lemas-sandbox/lemas/pkg/peparser"
)

type YaraScanner struct {
	rulesDir      string
	externalRules *ExternalYaraRules
}

func NewYaraScanner(rulesDir string) (*YaraScanner, error) {
	ext, loadErrs := LoadYaraRules(rulesDir)
	for _, e := range loadErrs {
		// Log parse errors but don't fail — built-in rules still work.
		_ = e
	}
	return &YaraScanner{rulesDir: rulesDir, externalRules: ext}, nil
}

// CalculateEntropy calculates the Shannon entropy of a byte slice (0.0 to 8.0)
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var frequencies [256]int64
	for _, b := range data {
		frequencies[b]++
	}
	var entropy float64
	length := float64(len(data))
	for _, count := range frequencies {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// ScanFile checks files on disk statically.
func (y *YaraScanner) ScanFile(path string) []RuleHit {
	var hits []RuleHit

	data, err := os.ReadFile(path)
	if err != nil {
		return hits
	}
	// 1. Check for executable headers
	isPE := len(data) > 2 && data[0] == 'M' && data[1] == 'Z'

	if isPE {
		// Calculate whole-file entropy (fast pre-check)
		entropy := CalculateEntropy(data)
		if entropy > 7.2 {
			hits = append(hits, RuleHit{
				RuleName:    "HighEntropyPackedPE",
				Engine:      "yara",
				Description: "The PE executable has extremely high entropy, indicating packing or encryption.",
				Severity:    "medium",
				MITRETTP:    "T1027",
				MatchedOn:   path,
				Evidence:    fmt.Sprintf("Shannon Entropy: %.2f", entropy),
			})
		}

		// Deep PE analysis via saferwall/pe — malformation-tolerant, richer than debug/pe
		peResult, err := peparser.Analyze(path)
		if err == nil && peResult != nil {
			for _, h := range peResult.Hits {
				hits = append(hits, RuleHit{
					RuleName:    h.RuleName,
					Engine:      h.Engine,
					Description: h.Description,
					Severity:    h.Severity,
					MITRETTP:    h.MITRETTP,
					MatchedOn:   h.MatchedOn,
					Evidence:    h.Evidence,
				})
			}
		}
	}

	// 2. Scan for malicious strings
	signatures := []struct {
		name     string
		pattern  []byte
		desc     string
		severity string
		mitre    string
	}{
		{
			name:     "AntiDebugIsDebuggerPresent",
			pattern:  []byte("IsDebuggerPresent"),
			desc:     "Contains debugger detection API string",
			severity: "low",
			mitre:    "T1497.001",
		},
		{
			name:     "MaliciousMutexName",
			pattern:  []byte("Global\\SandboxTestMutex"),
			desc:     "Contains typical testing sandbox mutex reference",
			severity: "medium",
			mitre:    "T1547",
		},
		{
			name:     "Base64PowershellExec",
			pattern:  []byte("powershell.exe -nop -w hidden -encodedcommand"),
			desc:     "Contains command line pattern for hidden base64 PowerShell execution",
			severity: "high",
			mitre:    "T1059.001",
		},
	}

	for _, sig := range signatures {
		if bytes.Contains(data, sig.pattern) {
			hits = append(hits, RuleHit{
				RuleName:    sig.name,
				Engine:      "yara",
				Description: sig.desc,
				Severity:    sig.severity,
				MITRETTP:    sig.mitre,
				MatchedOn:   path,
				Evidence:    fmt.Sprintf("Found byte sequence: %s", string(sig.pattern)),
			})
		}
	}

	// Also scan for dropped scripts/extensions in filename
	ext := filepath.Ext(path)
	if ext == ".vbs" || ext == ".ps1" || ext == ".bat" {
		hits = append(hits, RuleHit{
			RuleName:    "ScriptExecutableDrop",
			Engine:      "yara",
			Description: "Script file dropped in workspace.",
			Severity:    "low",
			MITRETTP:    "T1059",
			MatchedOn:   path,
			Evidence:    fmt.Sprintf("Extension: %s", ext),
		})
	}

	// External .yar rules
	if y.externalRules != nil {
		hits = append(hits, y.externalRules.MatchFile(path, data)...)
	}

	return hits
}

// ScanMemory scans raw memory dumps from isolated execution.
func (y *YaraScanner) ScanMemory(pid int, address string, data []byte) []RuleHit {
	var hits []RuleHit

	// Check if MZ header is present in unbacked heap memory
	if len(data) > 2 && data[0] == 'M' && data[1] == 'Z' {
		hits = append(hits, RuleHit{
			RuleName:    "UnbackedPEHeaderInMemory",
			Engine:      "yara",
			Description: "PE header (MZ) discovered in an unbacked/anonymous memory region.",
			Severity:    "critical",
			MITRETTP:    "T1055.002",
			MatchedOn:   fmt.Sprintf("PID %d Address %s", pid, address),
			Evidence:    "MZ magic bytes found at start of heap allocation",
		})
	}

	// Check entropy of memory region
	entropy := CalculateEntropy(data)
	if len(data) > 4096 && entropy > 7.4 {
		hits = append(hits, RuleHit{
			RuleName:    "HighEntropyMemoryRegion",
			Engine:      "yara",
			Description: "Memory region exhibits high entropy, suggesting shellcode or encrypted payload.",
			Severity:    "high",
			MITRETTP:    "T1620",
			MatchedOn:   fmt.Sprintf("PID %d Address %s", pid, address),
			Evidence:    fmt.Sprintf("Entropy: %.2f", entropy),
		})
	}

	// Simple string scans on dumped pages
	if bytes.Contains(data, []byte("mimikatz")) {
		hits = append(hits, RuleHit{
			RuleName:    "MimikatzFoundInMemory",
			Engine:      "yara",
			Description: "Mimikatz credential dumper string signature identified in memory.",
			Severity:    "critical",
			MITRETTP:    "T1003.001",
			MatchedOn:   fmt.Sprintf("PID %d Address %s", pid, address),
			Evidence:    "Matched string: mimikatz",
		})
	}

	// External .yar rules
	if y.externalRules != nil {
		hits = append(hits, y.externalRules.MatchMemory(pid, address, data)...)
	}

	return hits
}
