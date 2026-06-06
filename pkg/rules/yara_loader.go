package rules

// yara_loader.go — loads external .yar / .yara rule files from a directory.
//
// Supported string types:
//   $s = "literal"            plain string
//   $s = "literal" nocase     case-insensitive
//   $s = "literal" wide       UTF-16LE (searched as-is after encoding)
//   $s = { 4D 5A ?? 00 }      hex with ? / ?? wildcards
//   $s = /regex/              RE2 regex (optionally /regex/i for case-insensitive)
//
// Supported conditions:
//   any of them
//   all of them
//   N of them
//   any of ($prefix*)         named pattern group
//   $s1 and $s2               boolean AND of individual patterns
//   $s1 or  $s2               boolean OR  of individual patterns
//
// Scan cap: first 512 KB of content for performance.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

const yaraScanCap = 512 * 1024

// patternKind distinguishes how a pattern is matched.
type patternKind uint8

const (
	kindLiteral patternKind = iota
	kindHex
	kindRegex
)

// yaraPattern holds one compiled $string definition.
type yaraPattern struct {
	id      string
	kind    patternKind
	literal []byte         // kindLiteral and kindHex
	re      *regexp.Regexp // kindRegex
	nocase  bool
	wide    bool           // match UTF-16LE encoded form as well
	// hex wildcard mask: same length as literal; 0xFF = exact, 0x00 = wildcard byte
	hexMask []byte
}

// ExternalYaraRule is the compiled form of one parsed rule.
type ExternalYaraRule struct {
	Name        string
	Description string
	Severity    string
	MITRETTP    string
	Tags        []string
	patterns    []yaraPattern
	condition   yaraCondition
}

// yaraCondition describes how patterns must match.
type yaraCondition struct {
	mode        condMode // modeAny / modeAll / modeCount / modeBoolExpr
	minCount    int      // for modeCount
	groupPrefix string   // for modeAny/modeAll over a named group ($prefix*)
	boolTokens  []string // raw tokens for modeBoolean ("$s1","and","$s2", ...)
}

type condMode uint8

const (
	modeAny      condMode = iota // any of them (default)
	modeAll                      // all of them
	modeCount                    // N of them
	modeBoolExpr                 // $s1 and $s2 / $s1 or $s2
)

// ExternalYaraRules is the loaded + compiled rule set.
type ExternalYaraRules struct {
	rules []ExternalYaraRule
}

// ─── Public API ──────────────────────────────────────────────────────────────

func LoadYaraRules(dir string) (*ExternalYaraRules, []error) {
	var out ExternalYaraRules
	var errs []error

	entries, err := os.ReadDir(dir)
	if err != nil {
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
		loaded, parseErrs := parseYaraFile(path)
		errs = append(errs, parseErrs...)
		out.rules = append(out.rules, loaded...)
	}
	return &out, errs
}

func (ey *ExternalYaraRules) MatchFile(path string, data []byte) []RuleHit {
	return ey.match(data, path)
}

func (ey *ExternalYaraRules) MatchMemory(pid int, address string, data []byte) []RuleHit {
	return ey.match(data, fmt.Sprintf("PID %d @ %s", pid, address))
}

func (ey *ExternalYaraRules) MatchScript(content []byte, label string) []RuleHit {
	return ey.match(content, label)
}

// ─── Matching engine ─────────────────────────────────────────────────────────

func (ey *ExternalYaraRules) match(data []byte, label string) []RuleHit {
	buf := data
	if len(buf) > yaraScanCap {
		buf = buf[:yaraScanCap]
	}
	lowerBuf := bytes.ToLower(buf)

	var hits []RuleHit
	for _, rule := range ey.rules {
		if len(rule.patterns) == 0 {
			continue
		}

		// Evaluate each pattern once, build match set
		matchSet := make(map[string]bool, len(rule.patterns))
		for _, p := range rule.patterns {
			matchSet[p.id] = matchPattern(p, buf, lowerBuf)
		}

		triggered, evidence := evalCondition(rule.condition, rule.patterns, matchSet)
		if triggered {
			hits = append(hits, RuleHit{
				RuleName:    rule.Name,
				Engine:      "yara-external",
				Description: rule.Description,
				Severity:    nonEmpty(rule.Severity, "medium"),
				MITRETTP:    rule.MITRETTP,
				MatchedOn:   label,
				Evidence:    "Matched: " + evidence,
			})
		}
	}
	return hits
}

// matchPattern returns true if pattern p matches inside buf (lowerBuf pre-computed).
func matchPattern(p yaraPattern, buf, lowerBuf []byte) bool {
	switch p.kind {
	case kindRegex:
		if p.re == nil {
			return false
		}
		return p.re.Match(buf)

	case kindHex:
		return matchHexWithMask(buf, p.literal, p.hexMask)

	default: // kindLiteral
		target := buf
		needle := p.literal
		if p.nocase {
			target = lowerBuf
			needle = bytes.ToLower(p.literal)
		}
		if bytes.Contains(target, needle) {
			return true
		}
		// wide: also check UTF-16LE encoded form
		if p.wide {
			wide := toUTF16LE(p.literal)
			if bytes.Contains(buf, wide) {
				return true
			}
		}
		return false
	}
}

// matchHexWithMask performs byte-by-byte matching respecting 0x00 wildcard mask entries.
func matchHexWithMask(data, pattern, mask []byte) bool {
	if len(pattern) == 0 {
		return true
	}
	pLen := len(pattern)
	outer:
	for i := 0; i <= len(data)-pLen; i++ {
		for j := 0; j < pLen; j++ {
			if mask != nil && j < len(mask) && mask[j] == 0x00 {
				continue // wildcard byte — skip
			}
			if data[i+j] != pattern[j] {
				continue outer
			}
		}
		return true
	}
	return false
}

// evalCondition decides whether the rule fires given the match set.
func evalCondition(cond yaraCondition, patterns []yaraPattern, matchSet map[string]bool) (bool, string) {
	var matched []string
	for id, ok := range matchSet {
		if ok {
			matched = append(matched, id)
		}
	}
	evidence := strings.Join(matched, ", ")

	switch cond.mode {
	case modeAll:
		return len(matched) == len(patterns), evidence

	case modeCount:
		return len(matched) >= cond.minCount, evidence

	case modeBoolExpr:
		result := evalBoolTokens(cond.boolTokens, matchSet)
		return result, evidence

	default: // modeAny
		if cond.groupPrefix != "" {
			// any of ($prefix*)
			for id, ok := range matchSet {
				if ok && strings.HasPrefix(id, cond.groupPrefix) {
					return true, id
				}
			}
			return false, ""
		}
		return len(matched) > 0, evidence
	}
}

// evalBoolTokens evaluates a flat token list like ["$s1","and","$s2","or","$s3"]
// with left-to-right evaluation (AND binds tighter than OR in this simple model).
func evalBoolTokens(tokens []string, matchSet map[string]bool) bool {
	if len(tokens) == 0 {
		return false
	}
	// Split on "or" first, then evaluate each "and" clause
	orClauses := splitTokens(tokens, "or")
	for _, clause := range orClauses {
		andTerms := splitTokens(clause, "and")
		allTrue := true
		for _, termSlice := range andTerms {
			if len(termSlice) == 0 {
				continue
			}
			t := strings.TrimSpace(termSlice[0])
			if t == "" {
				continue
			}
			if strings.HasPrefix(t, "not ") {
				sub := strings.TrimPrefix(t, "not ")
				if matchSet[sub] {
					allTrue = false
					break
				}
			} else {
				if !matchSet[t] {
					allTrue = false
					break
				}
			}
		}
		if allTrue {
			return true
		}
	}
	return false
}

func splitTokens(tokens []string, sep string) [][]string {
	var out [][]string
	var cur []string
	for _, t := range tokens {
		if strings.ToLower(strings.TrimSpace(t)) == sep {
			out = append(out, cur)
			cur = nil
		} else {
			cur = append(cur, t)
		}
	}
	out = append(out, cur)
	return out
}

func toUTF16LE(ascii []byte) []byte {
	runes := []rune(string(ascii))
	u16 := utf16.Encode(runes)
	out := make([]byte, len(u16)*2)
	for i, v := range u16 {
		out[i*2] = byte(v)
		out[i*2+1] = byte(v >> 8)
	}
	return out
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ─── Parser ──────────────────────────────────────────────────────────────────

func parseYaraFile(path string) ([]ExternalYaraRule, []error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, []error{fmt.Errorf("yara_loader: open %s: %w", path, err)}
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, []error{fmt.Errorf("yara_loader: read %s: %w", path, err)}
	}

	var (
		rules []ExternalYaraRule
		errs  []error
	)
	i := 0
	for i < len(lines) {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") {
			i++
			continue
		}
		if strings.HasPrefix(line, "rule ") || strings.HasPrefix(line, "private rule ") || strings.HasPrefix(line, "global rule ") {
			rule, advance, parseErr := parseRuleBlock(lines, i)
			if parseErr != nil {
				errs = append(errs, fmt.Errorf("%s: %w", path, parseErr))
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

func parseRuleBlock(lines []string, start int) (ExternalYaraRule, int, error) {
	header := strings.TrimSpace(lines[start])
	// Strip modifiers
	header = strings.TrimPrefix(header, "private ")
	header = strings.TrimPrefix(header, "global ")
	after, _ := strings.CutPrefix(header, "rule ")

	// Split on ":" for tags, then strip trailing "{"
	parts := strings.SplitN(after, ":", 2)
	ruleName := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[0]), "{"))

	var tags []string
	if len(parts) == 2 {
		tagPart := strings.TrimRight(parts[1], " {")
		for _, t := range strings.Fields(tagPart) {
			tags = append(tags, t)
		}
	}

	rule := ExternalYaraRule{
		Name: ruleName,
		Tags: tags,
		condition: yaraCondition{mode: modeAny},
	}

	// Find opening brace
	i := start
	for i < len(lines) && !strings.Contains(lines[i], "{") {
		i++
	}
	i++ // past "{"

	section := ""
	var condLines []string

	for i < len(lines) {
		raw := lines[i]
		line := strings.TrimSpace(raw)

		if line == "}" {
			rule.condition = parseConditionExpr(condLines, rule.patterns)
			return rule, i + 1, nil
		}
		if line == "" || strings.HasPrefix(line, "//") {
			i++
			continue
		}

		switch {
		case strings.HasPrefix(line, "meta:"):
			section = "meta"
		case strings.HasPrefix(line, "strings:"):
			section = "strings"
		case strings.HasPrefix(line, "condition:"):
			section = "condition"
			// Condition may start on same line: "condition: any of them"
			rest := strings.TrimSpace(strings.TrimPrefix(line, "condition:"))
			if rest != "" {
				condLines = append(condLines, rest)
			}
		default:
			switch section {
			case "meta":
				parseMetaLine(line, &rule)
			case "strings":
				if p, err := parseStringLine(line); err == nil {
					rule.patterns = append(rule.patterns, p)
				}
			case "condition":
				condLines = append(condLines, line)
			}
		}
		i++
	}
	return rule, i, fmt.Errorf("rule %q: missing closing brace", ruleName)
}

// parseConditionExpr builds a yaraCondition from raw condition lines.
func parseConditionExpr(lines []string, patterns []yaraPattern) yaraCondition {
	expr := strings.ToLower(strings.Join(lines, " "))
	expr = strings.TrimSpace(expr)

	// "all of them"
	if strings.Contains(expr, "all of them") {
		return yaraCondition{mode: modeAll}
	}
	// "any of ($prefix*)"
	if idx := strings.Index(expr, "any of ($"); idx >= 0 {
		end := strings.Index(expr[idx:], ")")
		if end >= 0 {
			inner := expr[idx+9 : idx+end]
			prefix := strings.TrimSuffix(inner, "*")
			return yaraCondition{mode: modeAny, groupPrefix: "$" + prefix}
		}
	}
	// "any of them" or bare "any of"
	if strings.Contains(expr, "any of them") || expr == "any of" {
		return yaraCondition{mode: modeAny}
	}
	// "N of them"
	fields := strings.Fields(expr)
	for idx, f := range fields {
		if f == "of" && idx > 0 {
			n, err := strconv.Atoi(fields[idx-1])
			if err == nil {
				return yaraCondition{mode: modeCount, minCount: n}
			}
		}
	}
	// Boolean expression: "$s1 and $s2 or not $s3"
	hasBool := strings.Contains(expr, " and ") || strings.Contains(expr, " or ") || strings.Contains(expr, "not ")
	hasPattern := strings.Contains(expr, "$")
	if hasBool && hasPattern {
		tokens := tokeniseBoolExpr(expr)
		return yaraCondition{mode: modeBoolExpr, boolTokens: tokens}
	}
	// Fallback: any of them
	return yaraCondition{mode: modeAny}
}

func tokeniseBoolExpr(expr string) []string {
	// Split into words but keep $ identifiers intact
	raw := strings.Fields(expr)
	var tokens []string
	for _, w := range raw {
		w = strings.Trim(w, "()")
		if w != "" {
			tokens = append(tokens, w)
		}
	}
	return tokens
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

// parseStringLine parses a single YARA strings section line.
func parseStringLine(line string) (yaraPattern, error) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return yaraPattern{}, fmt.Errorf("no '=' in string line")
	}
	id := strings.TrimSpace(line[:eq])
	rest := strings.TrimSpace(line[eq+1:])

	// ── Regex string: $s = /pattern/ or /pattern/i ──────────────────────────
	if strings.HasPrefix(rest, "/") {
		return parseRegexPattern(id, rest)
	}

	// ── Hex string: $s = { 4D 5A ?? } ──────────────────────────────────────
	if strings.HasPrefix(rest, "{") {
		end := strings.LastIndex(rest, "}")
		if end < 0 {
			return yaraPattern{}, fmt.Errorf("unclosed hex string for %s", id)
		}
		inner := rest[1:end]
		literal, mask, err := parseHexString(inner)
		if err != nil {
			return yaraPattern{}, err
		}
		return yaraPattern{id: id, kind: kindHex, literal: literal, hexMask: mask}, nil
	}

	// ── Literal string: $s = "value" [nocase] [wide] ───────────────────────
	quote := byte(0)
	if strings.HasPrefix(rest, `"`) {
		quote = '"'
	} else if strings.HasPrefix(rest, "'") {
		quote = '\''
	}
	if quote == 0 {
		return yaraPattern{}, fmt.Errorf("unrecognised string syntax for %s", id)
	}

	closeIdx := strings.LastIndexByte(rest[1:], quote)
	if closeIdx < 0 {
		return yaraPattern{}, fmt.Errorf("unclosed string literal for %s", id)
	}
	inner := rest[1 : closeIdx+1]
	inner = unescapeYaraString(inner)
	mods := strings.ToLower(rest[closeIdx+2:])

	return yaraPattern{
		id:      id,
		kind:    kindLiteral,
		literal: []byte(inner),
		nocase:  strings.Contains(mods, "nocase"),
		wide:    strings.Contains(mods, "wide"),
	}, nil
}

// parseRegexPattern compiles a YARA /regex/ or /regex/i string.
func parseRegexPattern(id, rest string) (yaraPattern, error) {
	// Find closing slash (not escaped)
	closeIdx := -1
	for i := 1; i < len(rest); i++ {
		if rest[i] == '/' && rest[i-1] != '\\' {
			closeIdx = i
			break
		}
	}
	if closeIdx < 0 {
		return yaraPattern{}, fmt.Errorf("unclosed regex for %s", id)
	}
	pattern := rest[1:closeIdx]
	flags := rest[closeIdx+1:]

	if strings.Contains(flags, "i") {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return yaraPattern{}, fmt.Errorf("invalid regex %q for %s: %w", pattern, id, err)
	}
	return yaraPattern{id: id, kind: kindRegex, re: re}, nil
}

// parseHexString decodes a YARA hex string body into (bytes, mask).
// mask[i] == 0x00 means byte i is a wildcard (?? or ?).
func parseHexString(s string) ([]byte, []byte, error) {
	// Normalise: remove comments /* ... */
	for {
		start := strings.Index(s, "/*")
		if start < 0 {
			break
		}
		end := strings.Index(s[start:], "*/")
		if end < 0 {
			break
		}
		s = s[:start] + " " + s[start+end+2:]
	}

	var data, mask []byte
	fields := strings.Fields(s)
	for _, f := range fields {
		// Jump notation [n-m] or [n] — skip
		if strings.HasPrefix(f, "[") {
			continue
		}
		// Full wildcard ??
		if f == "??" {
			data = append(data, 0x00)
			mask = append(mask, 0x00)
			continue
		}
		// Nibble wildcard: ?X or X?
		if len(f) == 2 && (f[0] == '?' || f[1] == '?') {
			// treat as wildcard byte
			data = append(data, 0x00)
			mask = append(mask, 0x00)
			continue
		}
		b, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid hex byte %q: %w", f, err)
		}
		data = append(data, byte(b))
		mask = append(mask, 0xFF)
	}
	return data, mask, nil
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
