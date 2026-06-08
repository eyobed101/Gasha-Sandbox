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
	case monitor.EventProcessCreate:
		image, _ := ev.Data["Image"].(string)
		cmdline, _ := ev.Data["CommandLine"].(string)
		parentImage, _ := ev.Data["ParentImage"].(string)
		lowerImg := strings.ToLower(image)
		lowerCmd := strings.ToLower(cmdline)
		lowerParent := strings.ToLower(parentImage)
		baseName := lowerImg
		if idx := strings.LastIndexAny(lowerImg, `/\`); idx >= 0 {
			baseName = lowerImg[idx+1:]
		}

		// T1053.005 — schtasks.exe /create
		if baseName == "schtasks.exe" && strings.Contains(lowerCmd, "/create") {
			hits = append(hits, RuleHit{
				RuleName:    "ScheduledTaskCreatedViaCLI",
				Engine:      "sigma",
				Description: "schtasks.exe invoked with /create — scheduled task persistence via command line.",
				Severity:    "high",
				MITRETTP:    "T1053.005",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("Image: %s, CommandLine: %s", image, cmdline),
			})
		}

		// T1543.003 — sc.exe create / config
		if baseName == "sc.exe" &&
			(strings.Contains(lowerCmd, " create ") || strings.Contains(lowerCmd, " config ")) {
			hits = append(hits, RuleHit{
				RuleName:    "ServiceCreatedViaSC",
				Engine:      "sigma",
				Description: "sc.exe used to create or configure a Windows service — common malware persistence technique.",
				Severity:    "high",
				MITRETTP:    "T1543.003",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("CommandLine: %s", cmdline),
			})
		}

		// T1047 — wmic.exe process call create
		if baseName == "wmic.exe" && strings.Contains(lowerCmd, "process") &&
			strings.Contains(lowerCmd, "call create") {
			hits = append(hits, RuleHit{
				RuleName:    "WMICProcessCreate",
				Engine:      "sigma",
				Description: "wmic.exe used to spawn a process — common fileless execution and lateral movement vector.",
				Severity:    "high",
				MITRETTP:    "T1047",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("CommandLine: %s", cmdline),
			})
		}

		// T1059.001 — powershell spawned by non-interactive parent
		suspiciousParents := []string{"winword.exe", "excel.exe", "outlook.exe",
			"mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "rundll32.exe"}
		if baseName == "powershell.exe" || baseName == "pwsh.exe" {
			for _, sp := range suspiciousParents {
				if strings.HasSuffix(lowerParent, sp) {
					hits = append(hits, RuleHit{
						RuleName:    "PowerShellFromSuspiciousParent",
						Engine:      "sigma",
						Description: "PowerShell spawned from a suspicious parent process — common macro/script dropper pattern.",
						Severity:    "critical",
						MITRETTP:    "T1059.001",
						MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
						Evidence:    fmt.Sprintf("Parent: %s, CommandLine: %s", parentImage, cmdline),
					})
					break
				}
			}
		}

	
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

		// DGA detection — uses full bigram + consonant + length model
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

		hits = append(hits, RuleHit{
			RuleName:    "AntiAnalysisEvasionAttempted",
			Engine:      "sigma",
			Description: "Execution target actively checked for sandbox/virtualization hooks or debug environment indicators.",
			Severity:    "high",
			MITRETTP:    mitre,
			MatchedOn:   tech,
			Evidence:    details,
		})

	// ── Tier 1: WMI Activity ─────────────────────────────────────────────────
	case monitor.EventWMI:
		op, _ := ev.Data["wmi_operation"].(string)
		consumer, _ := ev.Data["wmi_consumer"].(string)
		query, _ := ev.Data["wmi_query"].(string)
		method, _ := ev.Data["wmi_method"].(string)
		subType, _ := ev.Data["subscription_type"].(string)
		namespace, _ := ev.Data["wmi_namespace"].(string)

		switch op {
		case "EventSubscription":
			hits = append(hits, RuleHit{
				RuleName:    "WMIEventSubscriptionPersistence",
				Engine:      "sigma",
				Description: "WMI event subscription created — a fileless persistence mechanism commonly used by APTs and commodity malware.",
				Severity:    "critical",
				MITRETTP:    "T1547.003",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("Type: %s, Namespace: %s, Consumer: %s, Query: %s", subType, namespace, consumer, query),
			})
		case "MethodExecution":
			// Win32_Process.Create via WMI is a classic execution bypass
			if strings.Contains(strings.ToLower(method), "process") ||
				strings.Contains(strings.ToLower(method), "create") {
				hits = append(hits, RuleHit{
					RuleName:    "WMIProcessExecution",
					Engine:      "sigma",
					Description: "WMI used to create or execute a process — common lateral movement and execution technique.",
					Severity:    "high",
					MITRETTP:    "T1047",
					MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
					Evidence:    fmt.Sprintf("Method: %s, Namespace: %s", method, namespace),
				})
			} else {
				hits = append(hits, RuleHit{
					RuleName:    "WMIMethodExecution",
					Engine:      "sigma",
					Description: "WMI method execution detected — potential living-off-the-land technique.",
					Severity:    "medium",
					MITRETTP:    "T1047",
					MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
					Evidence:    fmt.Sprintf("Method: %s, Namespace: %s", method, namespace),
				})
			}
		}

	// ── Tier 1: Scheduled Task ───────────────────────────────────────────────
	case monitor.EventSchedTask:
		op, _ := ev.Data["task_operation"].(string)
		taskName, _ := ev.Data["task_name"].(string)
		userCtx, _ := ev.Data["user_context"].(string)
		action, _ := ev.Data["action_name"].(string)

		switch op {
		case "Registered":
			hits = append(hits, RuleHit{
				RuleName:    "ScheduledTaskCreated",
				Engine:      "sigma",
				Description: "A new scheduled task was registered — frequently used for persistence and privilege escalation.",
				Severity:    "high",
				MITRETTP:    "T1053.005",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("Task: %s, UserContext: %s", taskName, userCtx),
			})
			// Escalate if task runs as SYSTEM
			if strings.Contains(strings.ToLower(userCtx), "system") ||
				strings.Contains(strings.ToLower(userCtx), "nt authority") {
				hits = append(hits, RuleHit{
					RuleName:    "ScheduledTaskAsSystem",
					Engine:      "sigma",
					Description: "Scheduled task registered to run as SYSTEM — high-privilege persistence.",
					Severity:    "critical",
					MITRETTP:    "T1053.005",
					MatchedOn:   fmt.Sprintf("PID %d Task: %s", ev.PID, taskName),
					Evidence:    fmt.Sprintf("UserContext: %s", userCtx),
				})
			}
		case "Updated":
			hits = append(hits, RuleHit{
				RuleName:    "ScheduledTaskModified",
				Engine:      "sigma",
				Description: "Existing scheduled task was modified — possible hijacking of a legitimate task for persistence.",
				Severity:    "high",
				MITRETTP:    "T1053.005",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("Task: %s, UserContext: %s", taskName, userCtx),
			})
		case "ActionStarted":
			// Only flag if task name looks suspicious (not Windows built-ins)
			lower := strings.ToLower(taskName)
			if !strings.HasPrefix(lower, `\microsoft\windows\`) {
				hits = append(hits, RuleHit{
					RuleName:    "SuspiciousScheduledTaskExecution",
					Engine:      "sigma",
					Description: "Non-Microsoft scheduled task executed — verify legitimacy.",
					Severity:    "medium",
					MITRETTP:    "T1053.005",
					MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
					Evidence:    fmt.Sprintf("Task: %s, Action: %s", taskName, action),
				})
			}
		}

	// ── Tier 1: Service Installation ─────────────────────────────────────────
	case monitor.EventServiceInstall:
		svcName, _ := ev.Data["service_name"].(string)
		imgPath, _ := ev.Data["service_imagepath"].(string)
		svcKey, _ := ev.Data["service_key"].(string)
		svcValue, _ := ev.Data["service_value"].(string)

		if svcValue == "ImagePath" || svcValue == "" {
			// New service with an executable path
			hits = append(hits, RuleHit{
				RuleName:    "ServiceInstalled",
				Engine:      "sigma",
				Description: "A new Windows service was installed — common persistence and privilege escalation mechanism.",
				Severity:    "high",
				MITRETTP:    "T1543.003",
				MatchedOn:   fmt.Sprintf("PID %d", ev.PID),
				Evidence:    fmt.Sprintf("Service: %s, ImagePath: %s, Key: %s", svcName, imgPath, svcKey),
			})

			// Escalate for services pointing to suspicious paths
			lowerImg := strings.ToLower(imgPath)
			suspiciousSvcPaths := []string{`\temp\`, `\tmp\`, `\appdata\`, `\users\public\`, `\programdata\`}
			for _, p := range suspiciousSvcPaths {
				if strings.Contains(lowerImg, p) {
					hits = append(hits, RuleHit{
						RuleName:    "ServiceInstalledFromSuspiciousPath",
						Engine:      "sigma",
						Description: "Windows service installed pointing to a user-writable path — strong indicator of malicious service installation.",
						Severity:    "critical",
						MITRETTP:    "T1543.003",
						MatchedOn:   fmt.Sprintf("PID %d Service: %s", ev.PID, svcName),
						Evidence:    fmt.Sprintf("ImagePath: %s (suspicious path: %s)", imgPath, p),
					})
					break
				}
			}
		}
	}

	// External .yml Sigma rules evaluated against every event
	if s.external != nil {
		hits = append(hits, s.external.Evaluate(ev)...)
	}

	return hits
}

// isDGADomain delegates to the statistical DGA detector in the monitor package.
// Uses bigram frequency + consonant-cluster ratio + label length.
func isDGADomain(domain string) bool {
	return monitor.IsDGADomainV2(domain)
}
