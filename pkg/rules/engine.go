package rules

import (
	"context"
	"path/filepath"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
)

// RuleHit represents a detection signature match from YARA or Sigma.
type RuleHit struct {
	RuleName    string            `json:"rule_name"`
	Engine      string            `json:"engine"`      // "yara", "yara-external", "sigma", "sigma-external"
	Description string            `json:"description"`
	Severity    string            `json:"severity"`    // "informational", "low", "medium", "high", "critical"
	MITRETTP    string            `json:"mitre_ttp"`   // e.g. "T1055.001"
	MatchedOn   string            `json:"matched_on"`  // context of match (file path, api param, etc.)
	Evidence    string            `json:"evidence"`    // extracted proof
	Meta        map[string]string `json:"meta,omitempty"` // all meta key=value pairs from the rule
}

// Engine aggregates the YARA and Sigma detection pipelines.
// Directory layout expected under rulesDir:
//
//	rulesDir/
//	├── yara/    ← .yar / .yara files
//	└── sigma/   ← .yml / .yaml Sigma rule files
type Engine struct {
	yaraEngine  *YaraScanner
	sigmaEngine *SigmaCorrelator
}

// NewEngine creates an Engine that loads rules from the standard subdirectory layout:
//   rulesDir/yara/   — YARA rules (.yar, .yara)
//   rulesDir/sigma/  — Sigma rules (.yml, .yaml)
func NewEngine(rulesDir string) (*Engine, error) {
	yaraScan, err := NewYaraScanner(filepath.Join(rulesDir, "yara"))
	if err != nil {
		return nil, err
	}

	sigmaCorr, err := NewSigmaCorrelatorWithDir(filepath.Join(rulesDir, "sigma"))
	if err != nil {
		return nil, err
	}

	return &Engine{
		yaraEngine:  yaraScan,
		sigmaEngine: sigmaCorr,
	}, nil
}

// NewEngineWithDirs creates an Engine with explicit separate directories for each engine.
// Use this when your YARA and Sigma rules live in non-standard paths.
func NewEngineWithDirs(yaraDir, sigmaDir string) (*Engine, error) {
	yaraScan, err := NewYaraScanner(yaraDir)
	if err != nil {
		return nil, err
	}
	sigmaCorr, err := NewSigmaCorrelatorWithDir(sigmaDir)
	if err != nil {
		return nil, err
	}
	return &Engine{
		yaraEngine:  yaraScan,
		sigmaEngine: sigmaCorr,
	}, nil
}

// ScanFile runs static YARA checks against a file on disk.
func (e *Engine) ScanFile(path string) []RuleHit {
	return e.yaraEngine.ScanFile(path)
}

// ScanMemory runs YARA checks against a raw memory buffer.
func (e *Engine) ScanMemory(pid int, address string, data []byte) []RuleHit {
	return e.yaraEngine.ScanMemory(pid, address, data)
}

// ScanScript runs inline YARA checks against a script block (PowerShell, AMSI, etc.).
func (e *Engine) ScanScript(content []byte, sourcePath string) []RuleHit {
	return e.yaraEngine.ScanScript(content, sourcePath)
}

// ProcessEvent runs Sigma correlation against a single telemetry event.
func (e *Engine) ProcessEvent(ctx context.Context, ev monitor.Event) []RuleHit {
	return e.sigmaEngine.Evaluate(ev)
}
