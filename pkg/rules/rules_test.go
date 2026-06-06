package rules_test

import (
	"os"
	"testing"

	"github.com/lemas-sandbox/lemas/pkg/rules"
)

func TestCalculateEntropyZero(t *testing.T) {
	data := make([]byte, 1024) // all zeros — minimal entropy
	e := rules.CalculateEntropy(data)
	if e != 0.0 {
		t.Errorf("expected 0.0 entropy for uniform data, got %.4f", e)
	}
}

func TestCalculateEntropyHigh(t *testing.T) {
	// Pseudo-random-looking byte sequence → high entropy
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i * 7 % 256)
	}
	e := rules.CalculateEntropy(data)
	if e < 7.0 {
		t.Errorf("expected entropy > 7.0 for high-variance data, got %.4f", e)
	}
}

func TestScanFileNotExist(t *testing.T) {
	scanner, _ := rules.NewYaraScanner("")
	hits := scanner.ScanFile("nonexistent_file_xyz.exe")
	if len(hits) != 0 {
		t.Errorf("expected 0 hits for missing file, got %d", len(hits))
	}
}

func TestScanFileScriptExtension(t *testing.T) {
	// Write a dummy .ps1 file
	f, _ := os.CreateTemp("", "test*.ps1")
	f.WriteString("Write-Host Hello")
	f.Close()
	defer os.Remove(f.Name())

	scanner, _ := rules.NewYaraScanner("")
	hits := scanner.ScanFile(f.Name())

	found := false
	for _, h := range hits {
		if h.RuleName == "ScriptExecutableDrop" {
			found = true
		}
	}
	if !found {
		t.Error("expected ScriptExecutableDrop hit for .ps1 file")
	}
}

func TestScanMemoryMZHeader(t *testing.T) {
	scanner, _ := rules.NewYaraScanner("")
	data := make([]byte, 8192)
	data[0] = 'M'
	data[1] = 'Z'

	hits := scanner.ScanMemory(1234, "0x1A0000", data)
	found := false
	for _, h := range hits {
		if h.RuleName == "UnbackedPEHeaderInMemory" {
			found = true
		}
	}
	if !found {
		t.Error("expected UnbackedPEHeaderInMemory hit for MZ magic in memory")
	}
}

func TestScanMemoryMimikatz(t *testing.T) {
	scanner, _ := rules.NewYaraScanner("")
	data := []byte("some garbage before mimikatz string here")

	hits := scanner.ScanMemory(999, "0x0", data)
	found := false
	for _, h := range hits {
		if h.RuleName == "MimikatzFoundInMemory" {
			found = true
		}
	}
	if !found {
		t.Error("expected MimikatzFoundInMemory hit")
	}
}
