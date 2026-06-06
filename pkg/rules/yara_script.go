package rules

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

// scriptSig defines a single script-level byte/string signature.
type scriptSig struct {
	name     string
	pattern  []byte
	desc     string
	severity string
	mitre    string
}

// powershellSignatures are pattern-matched case-insensitively against script content.
var powershellSignatures = []scriptSig{
	{
		name:     "PSInvokeExpression",
		pattern:  []byte("Invoke-Expression"),
		desc:     "Script uses Invoke-Expression (IEX) — common obfuscated execution primitive.",
		severity: "high",
		mitre:    "T1059.001",
	},
	{
		name:     "PSInvokeExpressionShort",
		pattern:  []byte("IEX("),
		desc:     "Script uses abbreviated IEX() invocation shorthand.",
		severity: "high",
		mitre:    "T1059.001",
	},
	{
		name:     "PSInvokeExpressionShortSpace",
		pattern:  []byte("IEX ("),
		desc:     "Script uses abbreviated IEX () invocation shorthand.",
		severity: "high",
		mitre:    "T1059.001",
	},
	{
		name:     "PSDownloadString",
		pattern:  []byte("DownloadString"),
		desc:     "Script downloads and executes remote content via .NET WebClient.",
		severity: "critical",
		mitre:    "T1059.001",
	},
	{
		name:     "PSWebClient",
		pattern:  []byte("New-Object Net.WebClient"),
		desc:     "Script instantiates a .NET WebClient for remote network access.",
		severity: "high",
		mitre:    "T1071.001",
	},
	{
		name:     "PSWebClientShort",
		pattern:  []byte("Net.WebClient"),
		desc:     "Script references .NET WebClient class.",
		severity: "medium",
		mitre:    "T1059.001",
	},
	{
		name:     "PSInvokeMimikatz",
		pattern:  []byte("Invoke-Mimikatz"),
		desc:     "Script contains Invoke-Mimikatz credential harvesting function.",
		severity: "critical",
		mitre:    "T1003.001",
	},
	{
		name:     "PSMimikatzString",
		pattern:  []byte("mimikatz"),
		desc:     "Script contains mimikatz string — credential dumper reference.",
		severity: "critical",
		mitre:    "T1003.001",
	},
	{
		name:     "PSAMSIBypassInit",
		pattern:  []byte("amsiInitFailed"),
		desc:     "Script attempts to set amsiInitFailed to bypass AMSI scanning.",
		severity: "critical",
		mitre:    "T1562.001",
	},
	{
		name:     "PSAMSIBypassMarshal",
		pattern:  []byte("InteropServices.Marshal"),
		desc:     "Script uses Marshal class to patch AMSI in-memory — known bypass technique.",
		severity: "critical",
		mitre:    "T1562.001",
	},
	{
		name:     "PSAMSIBypassContext",
		pattern:  []byte("AmsiScanBuffer"),
		desc:     "Script references AmsiScanBuffer — likely attempting AMSI hook patch.",
		severity: "critical",
		mitre:    "T1562.001",
	},
	{
		name:     "PSBase64EncodedCommand",
		pattern:  []byte("-EncodedCommand"),
		desc:     "Script uses -EncodedCommand flag for obfuscated PowerShell execution.",
		severity: "high",
		mitre:    "T1059.001",
	},
	{
		name:     "PSEncodedCommandShort",
		pattern:  []byte("-enc "),
		desc:     "Script uses abbreviated -enc flag (EncodedCommand shorthand).",
		severity: "high",
		mitre:    "T1059.001",
	},
	{
		name:     "PSReflectiveLoad",
		pattern:  []byte("[System.Reflection.Assembly]::Load"),
		desc:     "Script reflectively loads a .NET assembly from memory.",
		severity: "critical",
		mitre:    "T1620",
	},
	{
		name:     "PSLoadFile",
		pattern:  []byte("::LoadFile("),
		desc:     "Script loads a .NET assembly from a file path at runtime.",
		severity: "high",
		mitre:    "T1059.001",
	},
	{
		name:     "PSHiddenWindowNoProfile",
		pattern:  []byte("-WindowStyle Hidden"),
		desc:     "Script launches hidden PowerShell window — common dropper behaviour.",
		severity: "medium",
		mitre:    "T1059.001",
	},
	{
		name:     "PSBypassExecutionPolicy",
		pattern:  []byte("-ExecutionPolicy Bypass"),
		desc:     "Script bypasses PowerShell execution policy.",
		severity: "medium",
		mitre:    "T1059.001",
	},
	{
		name:     "PSShellcodeAlloc",
		pattern:  []byte("VirtualAlloc"),
		desc:     "Script calls VirtualAlloc — possible shellcode allocation from PowerShell.",
		severity: "critical",
		mitre:    "T1055",
	},
	{
		name:     "PSDumpLSASS",
		pattern:  []byte("lsass"),
		desc:     "Script references lsass process — possible credential dumping.",
		severity: "critical",
		mitre:    "T1003.001",
	},
}

// ScanScript performs inline YARA-style analysis on raw script content (PowerShell, VBScript, etc.).
// content is the raw bytes of the script block.
// sourcePath is a human-readable label for the match context (e.g. "PowerShell:4104:PID-1234").
func (y *YaraScanner) ScanScript(content []byte, sourcePath string) []RuleHit {
	var hits []RuleHit

	if len(content) == 0 {
		return hits
	}

	// Normalise to lower-case for pattern matching (patterns also stored lower-case for comparison)
	lower := bytes.ToLower(content)

	// 1. Run signature set (case-insensitive via lower-cased comparison)
	for _, sig := range powershellSignatures {
		if bytes.Contains(lower, bytes.ToLower(sig.pattern)) {
			hits = append(hits, RuleHit{
				RuleName:    sig.name,
				Engine:      "yara-script",
				Description: sig.desc,
				Severity:    sig.severity,
				MITRETTP:    sig.mitre,
				MatchedOn:   sourcePath,
				Evidence:    fmt.Sprintf("Matched pattern: %s", string(sig.pattern)),
			})
		}
	}

	// 2. Entropy check on script body — highly obfuscated scripts have entropy > 5.5
	entropy := CalculateEntropy(content)
	if entropy > 5.5 && len(content) > 256 {
		hits = append(hits, RuleHit{
			RuleName:    "HighEntropyScriptBlock",
			Engine:      "yara-script",
			Description: "Script block has unusually high entropy, indicating heavy obfuscation or encoding.",
			Severity:    "high",
			MITRETTP:    "T1027",
			MatchedOn:   sourcePath,
			Evidence:    fmt.Sprintf("Shannon entropy: %.2f (threshold 5.5)", entropy),
		})
	}

	// 3. Attempt base64 decode of any large base64 chunks and recursively scan
	deobfuscated := tryDeobfuscate(content)
	if deobfuscated != nil {
		subHits := y.ScanScript(deobfuscated, sourcePath+"[deobfuscated]")
		hits = append(hits, subHits...)
	}

	// 4. External .yar rules applied to script content
	if y.externalRules != nil {
		hits = append(hits, y.externalRules.MatchScript(content, sourcePath)...)
	}

	return hits
}

// tryDeobfuscate attempts common single-layer deobfuscation strategies and returns the
// decoded payload if successful, or nil if nothing was decoded.
func tryDeobfuscate(content []byte) []byte {
	s := strings.TrimSpace(string(content))

	// Strategy 1: pure base64 block (the whole content looks base64)
	if isLikelyBase64(s) {
		if decoded, err := base64.StdEncoding.DecodeString(s); err == nil && len(decoded) > 0 {
			return decoded
		}
		// Try URL-safe variant
		if decoded, err := base64.URLEncoding.DecodeString(s); err == nil && len(decoded) > 0 {
			return decoded
		}
	}

	// Strategy 2: strip backtick obfuscation (PowerShell `character insertion)
	stripped := strings.ReplaceAll(s, "`", "")
	if stripped != s {
		return []byte(stripped)
	}

	// Strategy 3: strip single-char string concatenation (e.g. 'I'+'E'+'X')
	// Simple heuristic: if content contains many "'+'", collapse them
	if strings.Count(s, "'+'")+strings.Count(s, `"+"`) > 5 {
		collapsed := strings.ReplaceAll(s, "'+' ", "")
		collapsed = strings.ReplaceAll(collapsed, `"+" `, "")
		collapsed = strings.ReplaceAll(collapsed, `'+'`, "")
		collapsed = strings.ReplaceAll(collapsed, `"+"`, "")
		collapsed = strings.Trim(collapsed, `"'`)
		if collapsed != s {
			return []byte(collapsed)
		}
	}

	return nil
}

// isLikelyBase64 returns true if the string looks like a base64 encoded blob.
func isLikelyBase64(s string) bool {
	if len(s) < 16 {
		return false
	}
	validChars := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			validChars++
		}
	}
	return float64(validChars)/float64(len(s)) > 0.92
}
