package rules

import (
	"fmt"
	"strings"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
)

type SigmaCorrelator struct {
	external *ExternalSigmaRules
}

func NewSigmaCorrelator() (*SigmaCorrelator, error) {
	return &SigmaCorrelator{}, nil
}

// NewSigmaCorrelatorWithDir creates a correlator that also loads external .yml rules from dir.
func NewSigmaCorrelatorWithDir(rulesDir string) (*SigmaCorrelator, error) {
	ext, _ := LoadSigmaRules(rulesDir) // parse errors are non-fatal
	return &SigmaCorrelator{external: ext}, nil
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

	// ── Task B: DNS-Client events ────────────────────────────────────────────
	case monitor.EventNetDNS:
		query, _ := ev.Data["dns_query"].(string)
		domain, _ := ev.Data["domain"].(string)
		if domain == "" {
			domain = query
		}

		// DGA detection heuristic: high-entropy hostname label
		if isDGADomain(domain) {
			hits = append(hits, RuleHit{
				RuleName:    "DGADomainDetected",
				Engine:      "sigma",
				Description: "DNS query to a high-entropy domain name consistent with Domain Generation Algorithm (DGA).",
				Severity:    "high",
				MITRETTP:    "T1568.002",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("Query: %s (entropy > threshold)", domain),
			})
		}

		// Known suspicious TLDs often used for C2 infrastructure
		lowerDomain := strings.ToLower(domain)
		suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".cc"}
		for _, tld := range suspiciousTLDs {
			if strings.HasSuffix(lowerDomain, tld) {
				hits = append(hits, RuleHit{
					RuleName:    "SuspiciousTLDDNSQuery",
					Engine:      "sigma",
					Description: "DNS query to a domain with a free/low-reputation TLD commonly used for malware C2.",
					Severity:    "medium",
					MITRETTP:    "T1071.004",
					MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
					Evidence:    fmt.Sprintf("Domain: %s (TLD: %s)", domain, tld),
				})
				break
			}
		}

	// ── Task B: Handle events ────────────────────────────────────────────────
	case monitor.EventHandleCreate:
		objectType, _ := ev.Data["object_type"].(string)
		objectName, _ := ev.Data["object_name"].(string)
		lowerName := strings.ToLower(objectName)

		// T1003.001 - LSASS handle open (credential dumping prerequisite)
		if strings.Contains(lowerName, "lsass") {
			hits = append(hits, RuleHit{
				RuleName:    "LSASSHandleOpen",
				Engine:      "sigma",
				Description: "Process opened a handle to lsass.exe — possible credential dumping attempt.",
				Severity:    "critical",
				MITRETTP:    "T1003.001",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("ObjectType: %s, ObjectName: %s", objectType, objectName),
			})
		}

		// Malware fingerprint mutex detection
		if strings.EqualFold(objectType, "Mutant") || strings.EqualFold(objectType, "Mutex") {
			hits = append(hits, RuleHit{
				RuleName:    "MalwareMutexCreation",
				Engine:      "sigma",
				Description: "Process created a named mutex — common malware singleton/fingerprint mechanism.",
				Severity:    "medium",
				MITRETTP:    "T1480",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("Mutex name: %s", objectName),
			})
		}

		// Named pipe access (lateral movement / IPC)
		if strings.Contains(lowerName, `\pipe\`) || strings.Contains(lowerName, `\named pipe\`) {
			hits = append(hits, RuleHit{
				RuleName:    "NamedPipeHandleAccess",
				Engine:      "sigma",
				Description: "Process opened a handle to a named pipe — possible inter-process communication or lateral movement channel.",
				Severity:    "low",
				MITRETTP:    "T1559.001",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("Pipe path: %s", objectName),
			})
		}

	case monitor.EventHandleDuplicate:
		objectName, _ := ev.Data["object_name"].(string)
		targetPID, _ := ev.Data["target_pid"].(int)
		lowerName := strings.ToLower(objectName)

		// Handle duplication to LSASS is a common credential-theft vector
		if strings.Contains(lowerName, "lsass") {
			hits = append(hits, RuleHit{
				RuleName:    "LSASSHandleDuplicated",
				Engine:      "sigma",
				Description: "Handle to lsass.exe was duplicated across processes — elevated credential theft risk.",
				Severity:    "critical",
				MITRETTP:    "T1003.001",
				MatchedOn:   fmt.Sprintf("PID %d → PID %d", ev.PID, targetPID),
				Evidence:    fmt.Sprintf("Duplicated handle to: %s", objectName),
			})
		}

	// ── Task C: PowerShell script block events ───────────────────────────────
	case monitor.EventPowerShell:
		scriptText, _ := ev.Data["script_block"].(string)
		lowerScript := strings.ToLower(scriptText)

		// Execution policy bypass via encoded command (T1059.001)
		if strings.Contains(lowerScript, "-encodedcommand") || strings.Contains(lowerScript, " -enc ") {
			hits = append(hits, RuleHit{
				RuleName:    "PSEncodedCommandExecution",
				Engine:      "sigma",
				Description: "PowerShell executed with an encoded command argument — obfuscated payload delivery.",
				Severity:    "high",
				MITRETTP:    "T1059.001",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    "Script block contains -EncodedCommand or -enc flag",
			})
		}

		// Download cradle (T1059.001 + T1105)
		if (strings.Contains(lowerScript, "downloadstring") || strings.Contains(lowerScript, "downloadfile")) &&
			strings.Contains(lowerScript, "http") {
			hits = append(hits, RuleHit{
				RuleName:    "PSDownloadCradle",
				Engine:      "sigma",
				Description: "PowerShell script contains a download cradle — remote payload fetching pattern.",
				Severity:    "critical",
				MITRETTP:    "T1105",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    "Script block contains HTTP download + execution pattern",
			})
		}

		// AMSI bypass (T1562.001)
		if strings.Contains(lowerScript, "amsi") &&
			(strings.Contains(lowerScript, "bypass") || strings.Contains(lowerScript, "disable") ||
				strings.Contains(lowerScript, "patch") || strings.Contains(lowerScript, "initfailed")) {
			hits = append(hits, RuleHit{
				RuleName:    "PSAMSIBypassAttempt",
				Engine:      "sigma",
				Description: "PowerShell script attempts to bypass or disable AMSI scanning.",
				Severity:    "critical",
				MITRETTP:    "T1562.001",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    "Script block contains AMSI bypass keyword cluster",
			})
		}

	// ── Task C: AMSI scan content events ─────────────────────────────────────
	case monitor.EventAMSIScan:
		appName, _ := ev.Data["app_name"].(string)
		contentName, _ := ev.Data["content_name"].(string)
		scanResult, _ := ev.Data["scan_result"].(string)

		// AMSI flagged the content as malicious
		if scanResult != "" && scanResult != "AMSI_RESULT_CLEAN" && scanResult != "1" {
			hits = append(hits, RuleHit{
				RuleName:    "AMSIContentDetection",
				Engine:      "sigma",
				Description: "AMSI flagged scanned content as potentially malicious.",
				Severity:    "high",
				MITRETTP:    "T1059.001",
				MatchedOn:   fmt.Sprintf("PID %d App: %s", ev.PID, appName),
				Evidence:    fmt.Sprintf("Content: %s, Result: %s", contentName, scanResult),
			})
		}

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

	// External .yml Sigma rules evaluated against every event
	if s.external != nil {
		hits = append(hits, s.external.Evaluate(ev)...)
	}

	return hits
}

// isDGADomain returns true if the domain exhibits DGA characteristics:
//   - host label length > 15, OR
//   - host label Shannon entropy > 3.5 bits
func isDGADomain(domain string) bool {
	if domain == "" {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}

	hostLabel := labels[0]
	if len(hostLabel) < 8 {
		return false
	}
	if len(hostLabel) > 15 {
		return true
	}

	// Compute Shannon entropy of the host label
	freq := make(map[rune]int)
	for _, c := range hostLabel {
		freq[c]++
	}
	n := float64(len(hostLabel))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * log2(p)
		}
	}
	return entropy > 3.5
}

// log2 computes log base-2 without importing math (avoids import cycle; math is already
// used in yara.go in the same package, so both files compile together fine).
func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Iterative natural log via Taylor series, then divide by ln(2)
	result := lnIter(x)
	return result / 0.6931471805599453
}

// lnIter approximates ln(x) using the identity ln(x) = 2*atanh((x-1)/(x+1)).
func lnIter(x float64) float64 {
	if x <= 0 {
		return 0
	}
	y := (x - 1) / (x + 1)
	y2 := y * y
	sum := 0.0
	term := y
	for i := 0; i < 40; i++ {
		sum += term / float64(2*i+1)
		term *= y2
	}
	return 2 * sum
}
