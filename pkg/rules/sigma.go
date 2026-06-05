package rules

import (
	"fmt"
	"github.com/lemas-sandbox/lemas/pkg/monitor"
	"strings"
)

type SigmaCorrelator struct{}

func NewSigmaCorrelator() (*SigmaCorrelator, error) {
	return &SigmaCorrelator{}, nil
}

// Evaluate performs signature and behavioral pattern matching on single events or chains.
func (s *SigmaCorrelator) Evaluate(ev monitor.Event) []RuleHit {
	var hits []RuleHit

	switch ev.EventType {
	case monitor.EventAPICall:
		apiName, _ := ev.Data["api_name"].(string)
		args, _ := ev.Data["args"].(map[string]interface{})

		// T1055.001 - DLL/Process Injection
		if apiName == "CreateRemoteThread" && args != nil {
			targetPID, _ := args["target_pid"].(float64)
			hits = append(hits, RuleHit{
				RuleName:    "SuspiciousCreateRemoteThread",
				Engine:      "sigma",
				Description: "Process attempted execution control hijack by spawning thread in remote address space.",
				Severity:    "high",
				MITRETTP:    "T1055.001",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("Target PID: %.0f, API: CreateRemoteThread", targetPID),
			})
		}

	case monitor.EventRegSet:
		key, _ := ev.Data["key"].(string)
		valName, _ := ev.Data["value_name"].(string)
		valData, _ := ev.Data["value_data"].(string)

		// T1547.001 - Registry Run Keys Persistence
		if strings.Contains(strings.ToLower(key), "\\currentversion\\run") {
			hits = append(hits, RuleHit{
				RuleName:    "RegistryPersistenceRunKey",
				Engine:      "sigma",
				Description: "Registry write detected in startup auto-run keys indicating local persistence setup.",
				Severity:    "high",
				MITRETTP:    "T1547.001",
				MatchedOn:   key,
				Evidence:    fmt.Sprintf("Key: %s, Value: %s -> %s", key, valName, valData),
			})
		}

	case monitor.EventFileWrite:
		path, _ := ev.Data["path"].(string)
		
		// T1547.001 - Drop in startup directory
		if strings.Contains(strings.ToLower(path), "\\start menu\\programs\\startup\\") {
			hits = append(hits, RuleHit{
				RuleName:    "FileDropStartupDir",
				Engine:      "sigma",
				Description: "File written inside Windows system startup folders for automatic execution.",
				Severity:    "high",
				MITRETTP:    "T1547.001",
				MatchedOn:   path,
				Evidence:    fmt.Sprintf("Dropped binary path: %s", path),
			})
		}

	case monitor.EventNetConnect:
		destIP, _ := ev.Data["dest_ip"].(string)
		destPort, _ := ev.Data["dest_port"].(float64)
		domain, _ := ev.Data["domain"].(string)

		// T1071 - C2 Beaconing / Direct connection
		hits = append(hits, RuleHit{
			RuleName:    "C2NetworkBeaconInitiated",
			Engine:      "sigma",
			Description: "Network outbound connection established by analyzed execution target.",
			Severity:    "medium",
			MITRETTP:    "T1071",
			MatchedOn:   fmt.Sprintf("%s:%d", destIP, int(destPort)),
			Evidence:    fmt.Sprintf("Target Domain: %s, Port: %.0f", domain, destPort),
		})

	case monitor.EventEvasion:
		tech, _ := ev.Data["technique"].(string)
		details, _ := ev.Data["details"].(string)
		mitre, _ := ev.Data["mitre_ttp"].(string)

		// T1497 - Evasion Detected
		hits = append(hits, RuleHit{
			RuleName:    "AntiAnalysisEvasionAttempted",
			Engine:      "sigma",
			Description: "Execution target actively checked for sandbox/virtualization hooks or debug environment indicators.",
			Severity:    "high",
			MITRETTP:    mitre,
			MatchedOn:   tech,
			Evidence:    details,
		})
	}

	return hits
}
