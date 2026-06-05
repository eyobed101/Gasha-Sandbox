package rules

import (
	"context"
	"github.com/lemas-sandbox/lemas/pkg/monitor"
)

// RuleHit represents a detection signature match from YARA or Sigma.
type RuleHit struct {
	RuleName    string   `json:"rule_name"`
	Engine      string   `json:"engine"`      // "yara" or "sigma"
	Description string   `json:"description"`
	Severity    string   `json:"severity"`    // "informational", "low", "medium", "high", "critical"
	MITRETTP    string   `json:"mitre_ttp"`   // E.g. "T1055.001"
	MatchedOn   string   `json:"matched_on"`  // Context of match (file path, api parameter, etc.)
	Evidence    string   `json:"evidence"`    // Extracted proof (regex match, value, stack)
}

// Engine aggregates our detection pipelines.
type Engine struct {
	yaraEngine  *YaraScanner
	sigmaEngine *SigmaCorrelator
}

func NewEngine(rulesDir string) (*Engine, error) {
	yaraScan, err := NewYaraScanner(rulesDir)
	if err != nil {
		return nil, err
	}

	sigmaCorr, err := NewSigmaCorrelator()
	if err != nil {
		return nil, err
	}

	return &Engine{
		yaraEngine:  yaraScan,
		sigmaEngine: sigmaCorr,
	}, nil
}

// ScanFile runs static file checks against our signature patterns.
func (e *Engine) ScanFile(path string) []RuleHit {
	return e.yaraEngine.ScanFile(path)
}

// ScanMemory runs matches against raw memory dump buffers.
func (e *Engine) ScanMemory(pid int, address string, data []byte) []RuleHit {
	return e.yaraEngine.ScanMemory(pid, address, data)
}

// ProcessEvents processes incoming telemetry streams in micro-batches and runs Sigma correlations.
func (e *Engine) ProcessEvent(ctx context.Context, ev monitor.Event) []RuleHit {
	return e.sigmaEngine.Evaluate(ev)
}
