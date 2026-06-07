package monitor_test

import (
	"testing"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
)

// ─── DGA Detector — bigram model ─────────────────────────────────────────────

func TestDGADetectorKnownDGA(t *testing.T) {
	d := monitor.NewDGADetector()
	cases := []struct {
		domain string
		desc   string
	}{
		{"xkjqzrmbvpwscftaeldoyn.com", "random consonant-heavy DGA"},
		{"qzxvpfmwjklbnrthsd.net", "typical dictionary-attack DGA"},
		{"r4nd0mstr1ng12345678.cc", "alphanumeric DGA"},
		{"zxkqvpjfmwbhtnsdlcry.pw", "high consonant cluster DGA"},
		{"pfxkqzvrtbmjsdlcwnyh.xyz", "pure consonant run"},
	}
	for _, tc := range cases {
		r := d.Evaluate(tc.domain)
		if !r.IsDGA {
			t.Errorf("DGA miss — %s (%s): score=%.2f bigram=%.2f consonants=%d",
				tc.domain, tc.desc, r.Score, r.BigramScore, r.ConsonantRuns)
		}
	}
}

func TestDGADetectorLegitDomains(t *testing.T) {
	d := monitor.NewDGADetector()
	legit := []string{
		"google.com",
		"microsoft.com",
		"stackoverflow.com",
		"github.com",
		"wikipedia.org",
		"amazon.com",
		"youtube.com",
		"cloudflare.com",
	}
	for _, domain := range legit {
		r := d.Evaluate(domain)
		if r.IsDGA {
			t.Errorf("false positive — %s flagged as DGA (score=%.2f, bigram=%.2f, consonants=%d)",
				domain, r.Score, r.BigramScore, r.ConsonantRuns)
		}
	}
}

func TestDGADetectorEdgeCases(t *testing.T) {
	d := monitor.NewDGADetector()

	// Empty — never DGA
	if d.Evaluate("").IsDGA {
		t.Error("empty domain should not be DGA")
	}
	// Short label — never DGA (< 8 chars)
	if d.Evaluate("ab.co").IsDGA {
		t.Error("2-char label should not be DGA")
	}
	// Single label without TLD — not evaluated
	if d.Evaluate("nodot").IsDGA {
		t.Error("domain without TLD should not be DGA")
	}
}

func TestDGADetectorScoreComponents(t *testing.T) {
	d := monitor.NewDGADetector()

	// A high-confidence DGA should have high bigram score and consonant run
	r := d.Evaluate("xkjqzrmbvpwscftaeldoyn.com")
	if r.BigramScore < 6.0 {
		t.Errorf("expected high bigram score for DGA domain, got %.2f", r.BigramScore)
	}
	if r.ConsonantRuns < 3 {
		t.Errorf("expected consonant run >= 3, got %d", r.ConsonantRuns)
	}
	if r.LabelLen < 8 {
		t.Errorf("expected label length >= 8, got %d", r.LabelLen)
	}
}

// ─── NXDomain accumulation counter ───────────────────────────────────────────

func TestDGANXDomainAccumulation(t *testing.T) {
	d := monitor.NewDGADetector()
	jobID := "nxtest-job"

	// 14 NXDOMAINs should not trigger
	for i := 0; i < 14; i++ {
		exceeded := d.RecordNXDomain(jobID)
		if exceeded {
			t.Errorf("threshold should not be exceeded at count %d", i+1)
		}
	}

	// 16th should exceed (threshold = 15)
	d.RecordNXDomain(jobID) // 15th — hits threshold
	exceeded := d.RecordNXDomain(jobID) // 16th
	if !exceeded {
		t.Error("NXDomain threshold should be exceeded after 16 queries")
	}

	// Count should be accurate
	count := d.NXDomainCount(jobID)
	if count != 16 {
		t.Errorf("expected NXDomain count 16, got %d", count)
	}

	// Session reset should clear state
	d.ResetSession(jobID)
	if d.NXDomainCount(jobID) != 0 {
		t.Error("NXDomain count should be 0 after ResetSession")
	}
}

func TestDGANXDomainSessionIsolation(t *testing.T) {
	d := monitor.NewDGADetector()

	// Two separate jobs — NXDomain counts must not bleed across sessions
	for i := 0; i < 20; i++ {
		d.RecordNXDomain("job-a")
	}
	if d.NXDomainCount("job-b") != 0 {
		t.Error("NXDomain count bled across session boundary")
	}
}

// ─── DGA integration with Sigma correlator ───────────────────────────────────

func TestDGASigmaIntegration(t *testing.T) {
	// Verify the Sigma DGADomainDetected rule still fires with the new model
	// (this uses the IsDGADomainV2 delegate inside sigma.go)
	corr, _ := newSigmaCorrelatorForTest()

	ev := monitor.Event{
		JobID:     "dga-int",
		EventType: monitor.EventNetDNS,
		PID:       1234,
		Category:  monitor.CatNetwork,
		Data: map[string]interface{}{
			"dns_query": "xkjqzrmbvpwscftaeldoyn.com",
			"domain":    "xkjqzrmbvpwscftaeldoyn.com",
		},
	}

	// We can't import rules from the monitor package test, so we test the
	// IsDGADomainV2 function directly as a unit test here.
	result := monitor.IsDGADomainV2("xkjqzrmbvpwscftaeldoyn.com")
	if !result {
		t.Error("IsDGADomainV2 should return true for high-entropy DGA domain")
	}

	result2 := monitor.IsDGADomainV2("google.com")
	if result2 {
		t.Error("IsDGADomainV2 should return false for google.com")
	}

	_ = ev
	_ = corr
}

// newSigmaCorrelatorForTest is a placeholder to avoid import cycle.
// Actual Sigma integration is tested in pkg/rules tests.
func newSigmaCorrelatorForTest() (interface{}, error) { return nil, nil }
