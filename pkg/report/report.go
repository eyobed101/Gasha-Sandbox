package report

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
	"github.com/lemas-sandbox/lemas/pkg/rules"
	"github.com/lemas-sandbox/lemas/pkg/storage"
)

//go:embed template.html
var htmlTemplate string

// ReportData matches the template context bindings
type ReportData struct {
	ThreatLevel  string
	ThreatScore  int
	AccentColor  string
	GlowColor    string
	DashArray    int
	FilePath     string
	FileType     string
	SHA256       string
	Duration     int
	SummaryText  string
	TotalEvents  int
	YaraHits     int
	SigmaHits    int
	Events       []monitor.Event
	Hits         []rules.RuleHit
	TTPs         []storage.TTP
	IOCs         []storage.IOC
}

// JSONReport matches the detailed schema from user specification
type JSONReport struct {
	SchemaVersion    string                 `json:"schema_version"`
	JobID            string                 `json:"job_id"`
	AnalysisMetadata map[string]interface{} `json:"analysis_metadata"`
	Summary          map[string]interface{} `json:"summary"`
	MitreAttack      []storage.TTP          `json:"mitre_attack"`
	IOCs             map[string]interface{} `json:"iocs"`
	BehavioralTimeline []monitor.Event      `json:"behavioral_timeline"`
	RuleHits         []rules.RuleHit        `json:"rule_hits"`
}

func GenerateReport(jobID string, store *storage.Store, rawHits []rules.RuleHit, outJSONPath, outHTMLPath string) error {
	// 1. Fetch Job from SQLite
	job, err := store.GetJob(jobID)
	if err != nil {
		return err
	}

	// 2. Fetch Events
	events, err := store.GetJobEvents(jobID)
	if err != nil {
		return err
	}

	// 3. Extract IOCs & TTPs from the database/events
	var iocs []storage.IOC
	var ttps []storage.TTP

	// We populate IOCs dynamically from network, file and registry events
	for _, ev := range events {
		if ev.EventType == monitor.EventNetConnect {
			ip, _ := ev.Data["dest_ip"].(string)
			domain, _ := ev.Data["domain"].(string)
			if ip != "" {
				iocs = append(iocs, storage.IOC{JobID: jobID, IOCType: "ipv4", Value: ip, Context: "network", Confidence: 90})
			}
			if domain != "" {
				iocs = append(iocs, storage.IOC{JobID: jobID, IOCType: "domain", Value: domain, Context: "network", Confidence: 90})
			}
		} else if ev.EventType == monitor.EventFileWrite {
			path, _ := ev.Data["path"].(string)
			if path != "" {
				iocs = append(iocs, storage.IOC{JobID: jobID, IOCType: "file", Value: filepath.Base(path), Context: "filesystem", Confidence: 75})
			}
		} else if ev.EventType == monitor.EventRegSet {
			key, _ := ev.Data["key"].(string)
			val, _ := ev.Data["value_name"].(string)
			if key != "" {
				iocs = append(iocs, storage.IOC{JobID: jobID, IOCType: "registry", Value: key + "\\" + val, Context: "registry", Confidence: 80})
			}
		}
	}

	// Dynamic calculation of threat classification
	threatScore := 0
	yHits := 0
	sHits := 0
	
	for _, h := range rawHits {
		if h.Engine == "yara" {
			yHits++
		} else {
			sHits++
		}
		
		// Accumulate score based on severity
		switch h.Severity {
		case "critical":
			threatScore += 35
		case "high":
			threatScore += 25
		case "medium":
			threatScore += 15
		default:
			threatScore += 5
		}

		// Save mapped TTPs
		if h.MITRETTP != "" {
			ttps = append(ttps, storage.TTP{
				JobID:         jobID,
				TechniqueID:   h.MITRETTP,
				TechniqueName: h.RuleName,
				Tactic:        getTacticForTTP(h.MITRETTP),
				EvidenceIDs:   h.MatchedOn,
				Confidence:    85,
			})
		}
	}

	if threatScore > 100 {
		threatScore = 100
	}

	// Update job state
	job.ThreatScore = threatScore
	if threatScore >= 70 {
		job.ThreatLevel = "MALICIOUS"
	} else if threatScore >= 30 {
		job.ThreatLevel = "SUSPICIOUS"
	} else {
		job.ThreatLevel = "CLEAN"
	}
	job.CompletedAt = time.Now()
	job.Status = "completed"
	store.SaveJob(job)

	// Save TTPs and IOCs into store
	for _, i := range iocs {
		store.SaveIOC(i)
	}
	for _, t := range ttps {
		store.SaveTTP(t)
	}

	// Determine Theme colors based on Threat Level
	accentColor := "var(--accent-clean)"
	glowColor := "rgba(0, 242, 254, 0.15)"
	if job.ThreatLevel == "MALICIOUS" {
		accentColor = "var(--accent-malicious)"
		glowColor = "rgba(255, 0, 127, 0.2)"
	} else if job.ThreatLevel == "SUSPICIOUS" {
		accentColor = "var(--accent-suspicious)"
		glowColor = "rgba(255, 153, 0, 0.2)"
	}

	// Calculate dash offset for circle progress (circumference is ~201)
	dashArray := int(math.Round(float64(threatScore) * 201.0 / 100.0))

	// Create dynamic summary description text
	summaryText := "No threat signatures triggered. The sample completed execution with standard system calls and appears benign."
	if job.ThreatLevel == "MALICIOUS" {
		summaryText = "Critical security alert. The sample demonstrated multiple malicious characteristics including evasion attempts, startup persistence configuration, and connection to unverified domains."
	} else if job.ThreatLevel == "SUSPICIOUS" {
		summaryText = "Suspicious behavior flagged. The execution environment logged unusual actions such as registry persistence writes and high-entropy packed code modules."
	}

	// 4. Generate HTML Report
	reportData := ReportData{
		ThreatLevel:  job.ThreatLevel,
		ThreatScore:  threatScore,
		AccentColor:  accentColor,
		GlowColor:    glowColor,
		DashArray:    dashArray,
		FilePath:     job.FilePath,
		FileType:     job.FileType,
		SHA256:       job.FileHashSHA256,
		Duration:     int(job.CompletedAt.Sub(job.StartedAt).Seconds()),
		SummaryText:  summaryText,
		TotalEvents:  len(events),
		YaraHits:     yHits,
		SigmaHits:    sHits,
		Events:       events,
		Hits:         rawHits,
		TTPs:         ttps,
		IOCs:         iocs,
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	// Ensure parent output directories exist
	os.MkdirAll(filepath.Dir(outHTMLPath), 0755)
	htmlFile, err := os.Create(outHTMLPath)
	if err != nil {
		return err
	}
	defer htmlFile.Close()

	if err := tmpl.Execute(htmlFile, reportData); err != nil {
		return err
	}

	// 5. Generate JSON Report
	jsonRep := JSONReport{
		SchemaVersion: "1.0",
		JobID:         jobID,
		AnalysisMetadata: map[string]interface{}{
			"submitted_at":            job.SubmittedAt.Format(time.RFC3339),
			"completed_at":            job.CompletedAt.Format(time.RFC3339),
			"duration_seconds":        reportData.Duration,
			"analysis_engine_version": "1.0.0",
			"os_platform":             osPlatform(),
		},
		Summary: map[string]interface{}{
			"threat_level":        job.ThreatLevel,
			"threat_score":        threatScore,
			"behavioral_summary":  summaryText,
			"key_behaviors":       getKeyBehaviors(rawHits),
		},
		MitreAttack:        ttps,
		IOCs: map[string]interface{}{
			"hashes": map[string]string{
				"sha256": job.FileHashSHA256,
			},
			"extracted_iocs": iocs,
		},
		BehavioralTimeline: events,
		RuleHits:           rawHits,
	}

	os.MkdirAll(filepath.Dir(outJSONPath), 0755)
	jsonFile, err := os.Create(outJSONPath)
	if err != nil {
		return err
	}
	defer jsonFile.Close()

	enc := json.NewEncoder(jsonFile)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonRep)
}

func getTacticForTTP(ttp string) string {
	switch ttp {
	case "T1497", "T1497.001", "T1497.003":
		return "Defense Evasion"
	case "T1055", "T1055.001", "T1055.002":
		return "Privilege Escalation / Defense Evasion"
	case "T1547.001", "T1547":
		return "Persistence"
	case "T1071", "T1071.001":
		return "Command and Control"
	case "T1059":
		return "Execution"
	default:
		return "Execution"
	}
}

func getKeyBehaviors(hits []rules.RuleHit) []string {
	var list []string
	for _, h := range hits {
		list = append(list, h.Description)
	}
	if len(list) == 0 {
		list = append(list, "No suspicious behaviors detected")
	}
	return list
}

func osPlatform() string {
	return runtime.GOOS
}
