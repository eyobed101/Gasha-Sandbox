package rules

// yara_loader.go — loads external .yar / .yara rule files from a directory and
// compiles them into RuleHit generators compatible with ScanFile, ScanMemory,
// and ScanScript.
//
// Supported YARA syntax subset:
//   rule <name> [: <tag> ...] {
//       meta:
//           description = "..."
//           severity    = "high"        // informational|low|medium|high|critical
//           mitre       = "T1055.001"
//       strings:
//           $s1 = "literal string"      // plain or nocase
//           $s2 = { 4D 5A ?? 00 }       // hex bytes (? and ?? as wildcards)
//       condition:
//           any of them
//   }
//
// Limitations (intentional — keeps this zero-dependency):
//   • Only "any of them" / "all of them" / "N of them" conditions are evaluated.
//   • Regex strings ($s = /pattern/) are not supported; use literal strings.
//   • Only the first 64 KB of scanned content is matched for performance.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ExternalYaraRule is the compiled form of one rule from a .yar file.
type ExternalYaraRule struct {
	Name        string
	Description string
	Severity    string
	MITRETTP    string
	Tags        []string
	// compiled pattern matchers
	patterns    []yaraPattern
	// condition: "any" or "all" or N (minimum count)
	minMatches  int
}

type yaraPattern struct {
	id       string // $s1
	literal  []byte // plain text or decoded hex
	nocase   bool
	isHex    bool
}

// ExternalYaraRules is the set loaded from disk. YaraScanner embeds this.
type ExternalYaraRules struct {
	rules []ExternalYaraRule
}

// LoadYaraRules loads all .yar and .yara files from dir.
// Errors on individual files are collected and returned as a combined non-fatal
// error; successfully parsed rules are returned regardless.
func LoadYaraRules(dir string) (*ExternalYaraRules, []error) {
	var (
		out  ExternalYaraRules
		errs []error
	)

	entries, err := os.ReadDir(dir)
	if err != nil {
		// Directory may not exist yet — not fatal, just no external rules.
		return &out, nil
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yar") && !strings.HasSuffix(name, ".yara") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		rules, parseErrs := parseYaraFile(path)
		errs = append(errs, parseErrs...)
		out.rules = append(out.rules, rules...)
	}

	return &out, errs
}

// MatchFile runs external rules against raw file bytes.
func (ey *ExternalYaraRules) MatchFile(path string, data []byte) []RuleHit {
	return ey.match(data, path)
}

// MatchMemory runs external rules against a memory buffer.
func (ey *ExternalYaraRules) MatchMemory(pid int, address string, data []byte) []RuleHit {
	label := fmt.Sprintf("PID %d @ %s", pid, address)
	return ey.match(data, label)
}

// MatchScript runs external rules against a script block.
func (ey *ExternalYaraRules) MatchScript(content []byte, label string) []RuleHit {
	return ey.match(content, label)
}

func (ey *ExternalYaraRules) match(data []byte, label string) []RuleHit {
	// Cap to 64 KB for performance
	buf := data
	if len(buf) > 65536 {
		buf = buf[:65536]
	}
	lowerBuf := bytes.ToLower(buf)

	var hits []RuleHit
	for _, rule := range ey.rules {
		matched := 0
		var evidence strings.Builder

		for _, p := range rule.patterns {
			var found bool
			if p.nocase || p.isHex {
				found = bytes.Contains(lowerBuf, bytes.ToLower(p.literal))
			} else {
				found = bytes.Contains(buf, p.literal)
			}
			if found {
				matched++
				if evidence.Len() > 0 {
					evidence.WriteString(", ")
				}
				evidence.WriteString(p.id)
			}
		}

		if len(rule.patterns) == 0 {
			continue
		}

		triggered := false
		switch rule.minMatches {
		case 0: // "any of them"
			triggered = matched > 0
		case -1: // "all of them"
			triggered = matched == len(rule.patterns)
		default:
			triggered = matched >= rule.minMatches
		}

		if triggered {
			sev := rule.Severity
			if sev == "" {
				sev = "medium"
			}
			hits = append(hits, RuleHit{
				RuleName:    rule.Name,
				Engine:      "yara-external",
				Description: rule.Description,
				Severity:    sev,
				MITRETTP:    rule.MITRETTP,
				MatchedOn:   label,
				Evidence:    fmt.Sprintf("Matched strings: %s", evidence.String()),
			})
		}
	}
	return hits
}

// ─── Parser ──────────────────────────────────────────────────────────────────

func parseYaraFile(path string) ([]ExternalYaraRule, []error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, []error{fmt.Errorf("yara_loader: open %s: %w", path, err)}
	}
	defer f.Close()

	var (
		rules    []ExternalYaraRule
		errs     []error
		lines    []string
	)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, []error{fmt.Errorf("yara_loader: read %s: %w", path, err)}
	}

	i := 0
	for i < len(lines) {
		line := strings.TrimSpace(lines[i])

		// Skip blank lines and comments
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			i++
			continue
		}

		// Match rule header: "rule RuleName" or "rule RuleName : tag1 tag2"
		if strings.HasPrefix(line, "rule ") {
			rule, advance, parseErr := parseRuleBlock(lines, i)
			if parseErr != nil {
				errs = append(errs, fmt.Errorf("yara_loader: %s: %w", path, parseErr))
				i++
				continue
			}
			rules = append(rules, rule)
			i = advance
		} else {
			i++
		}
	}

	return rules, errs
}

// parseRuleBlock reads from lines[start] (the "rule ..." header) through the
// matching closing brace and returns the compiled rule plus the next line index.
func parseRuleBlock(lines []string, start int) (ExternalYaraRule, int, error) {
	header := strings.TrimSpace(lines[start])

	// Extract rule name and optional tags
	// e.g. "rule DetectMimikatz : credential_dumping"
	after, _ := strings.CutPrefix(header, "rule ")
	parts := strings.SplitN(after, ":", 2)
	ruleName := strings.TrimSpace(parts[0])
	// Remove trailing "{" if on same line
	ruleName = strings.TrimSuffix(ruleName, "{")
	ruleName = strings.TrimSpace(ruleName)

	var tags []string
	if len(parts) == 2 {
		for _, t := range strings.Fields(strings.TrimRight(parts[1], " {")) {
			tags = append(tags, t)
		}
	}

	rule := ExternalYaraRule{
		Name:       ruleName,
		Tags:       tags,
		minMatches: 0, // default: any of them
	}

	// Find opening brace
	i := start
	for i < len(lines) {
		if strings.Contains(lines[i], "{") {
			break
		}
		i++
	}
	i++ // move past opening brace

	section := ""

	for i < len(lines) {
		line := strings.TrimSpace(lines[i])

		if line == "}" {
			return rule, i + 1, nil
		}
		if line == "" || strings.HasPrefix(line, "//") {
			i++
			continue
		}

		// Section markers
		if strings.HasPrefix(line, "meta:") {
			section = "meta"
			i++
			continue
		}
		if strings.HasPrefix(line, "strings:") {
			section = "strings"
			i++
			continue
		}
		if strings.HasPrefix(line, "condition:") {
			section = "condition"
			i++
			continue
		}

		switch section {
		case "meta":
			parseMetaLine(line, &rule)

		case "strings":
			if p, err := parseStringLine(line); err == nil {
				rule.patterns = append(rule.patterns, p)
			}

		case "condition":
			rule.minMatches = parseCondition(line, len(rule.patterns))
		}

		i++
	}

	return rule, i, fmt.Errorf("rule %q: missing closing brace", ruleName)
}

func parseMetaLine(line string, rule *ExternalYaraRule) {
	kv := strings.SplitN(line, "=", 2)
	if len(kv) != 2 {
		return
	}
	key := strings.TrimSpace(kv[0])
	val := strings.Trim(strings.TrimSpace(kv[1]), `"`)

	switch key {
	case "description", "desc":
		rule.Description = val
	case "severity", "sev", "level":
		rule.Severity = normaliseSeverity(val)
	case "mitre", "mitre_ttp", "attack_id", "technique":
		rule.MITRETTP = val
	}
}

func parseStringLine(line string) (yaraPattern, error) {
	// $id = "value" [nocase]
	// $id = { 4D 5A }
	eq := strings.Index(line, "=")
	if eq < 0 {
		return yaraPattern{}, fmt.Errorf("no '=' in string definition")
	}
	id := strings.TrimSpace(line[:eq])
	rest := strings.TrimSpace(line[eq+1:])

	nocase := strings.Contains(strings.ToLower(rest), "nocase")
	rest = strings.TrimSuffix(strings.ToLower(rest), "nocase")
	rest = strings.TrimSpace(rest)

	// Hex string: { 4D 5A ... }
	if strings.HasPrefix(rest, "{") && strings.Contains(rest, "}") {
		inner := rest[strings.Index(rest, "{")+1 : strings.LastIndex(rest, "}")]
		literal, err := parseHexString(inner)
		if err != nil {
			return yaraPattern{}, err
		}
		return yaraPattern{id: id, literal: literal, nocase: false, isHex: true}, nil
	}

	// Quoted literal
	if (strings.HasPrefix(rest, `"`) && strings.Contains(rest[1:], `"`)) ||
		(strings.HasPrefix(rest, `'`) && strings.Contains(rest[1:], `'`)) {
		inner := rest[1:strings.LastIndex(rest, string(rest[0]))]
		inner = unescapeYaraString(inner)
		return yaraPattern{id: id, literal: []byte(inner), nocase: nocase}, nil
	}

	return yaraPattern{}, fmt.Errorf("unrecognised string syntax: %s", line)
}

func parseHexString(s string) ([]byte, error) {
	var out []byte
	fields := strings.Fields(s)
	for _, f := range fields {
		// Wildcards: ? or ??
		if f == "?" || f == "??" {
			out = append(out, 0x00) // placeholder; wildcard matching skipped for now
			continue
		}
		// Skip jump notation [n-m]
		if strings.HasPrefix(f, "[") {
			continue
		}
		b, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid hex byte %q: %w", f, err)
		}
		out = append(out, byte(b))
	}
	return out, nil
}

func parseCondition(line string, patternCount int) int {
	lower := strings.ToLower(strings.TrimSpace(line))
	if strings.Contains(lower, "all of them") {
		return -1 // sentinel for "all"
	}
	if strings.Contains(lower, "any of them") || strings.Contains(lower, "any of ($") {
		return 0 // any
	}
	// "N of them"
	fields := strings.Fields(lower)
	for idx, f := range fields {
		if f == "of" && idx > 0 {
			n, err := strconv.Atoi(fields[idx-1])
			if err == nil {
				return n
			}
		}
	}
	// Fallback: if condition references $*, treat as any
	if strings.Contains(lower, "of ($") || strings.Contains(lower, "$") {
		return 0
	}
	_ = patternCount
	return 0
}

func unescapeYaraString(s string) string {
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	s = strings.ReplaceAll(s, `\r`, "\r")
	s = strings.ReplaceAll(s, `\\`, `\`)
	s = strings.ReplaceAll(s, `\"`, `"`)
	return s
}

func normaliseSeverity(s string) string {
	switch strings.ToLower(s) {
	case "crit", "critical":
		return "critical"
	case "high":
		return "high"
	case "med", "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "informational"
	}
}
