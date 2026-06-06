package rules

// sigma_loader.go — loads standard Sigma rule files (.yml) from a directory
// and compiles them into runtime detectors evaluated by SigmaCorrelator.
//
// Supported Sigma structure:
//   title, id, status, description, tags (mitre attack.tXXXX), level,
//   logsource (category/product), detection (keywords / field: value maps),
//   condition (keywords | selection, 1 of them, all of them)
//
// Scope deliberately limited to the subset used in the Sigma community rules
// that target process, network, file, registry, and PowerShell event categories.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
)

// sigmaRuleFile mirrors the top-level structure of a .yml Sigma rule.
type sigmaRuleFile struct {
	Title       string                 `yaml:"title"`
	ID          string                 `yaml:"id"`
	Status      string                 `yaml:"status"`
	Description string                 `yaml:"description"`
	Level       string                 `yaml:"level"`
	Tags        []string               `yaml:"tags"`
	Logsource   sigmaLogsource         `yaml:"logsource"`
	Detection   map[string]interface{} `yaml:"detection"`
}

type sigmaLogsource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// compiledSigmaRule is the runtime form after parsing.
type compiledSigmaRule struct {
	Name        string
	Description string
	Severity    string
	MITRETTP    string
	// Which monitor.Event categories / types this rule targets
	targetCategories []string
	targetEventTypes []string
	// Compiled matchers: list of field→values groups (OR within group, AND across groups)
	selectors  []sigmaSelector
	// condition: "any" or "all"
	conditionAny bool
	// keyword matchers (flat list of strings searched across all event data)
	keywords []string
}

// sigmaSelector is one "selection_X" block: a map of fieldName → []values.
// The rule fires if field contains ANY of the values (case-insensitive).
type sigmaSelector struct {
	name   string
	fields map[string][]string // field → accepted values
}

// ExternalSigmaRules is the set loaded from disk.
type ExternalSigmaRules struct {
	rules []compiledSigmaRule
}

// LoadSigmaRules loads all .yml files in dir that look like Sigma rules.
func LoadSigmaRules(dir string) (*ExternalSigmaRules, []error) {
	var (
		out  ExternalSigmaRules
		errs []error
	)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return &out, nil // non-existent dir is fine
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".yml") &&
			!strings.HasSuffix(strings.ToLower(e.Name()), ".yaml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		rule, parseErr := parseSigmaFile(path)
		if parseErr != nil {
			errs = append(errs, parseErr)
			continue
		}
		if rule != nil {
			out.rules = append(out.rules, *rule)
		}
	}

	return &out, errs
}

// Evaluate runs all loaded external Sigma rules against a single event.
func (es *ExternalSigmaRules) Evaluate(ev monitor.Event) []RuleHit {
	var hits []RuleHit
	for _, rule := range es.rules {
		if !rule.matchesEventScope(ev) {
			continue
		}
		if rule.matches(ev) {
			hits = append(hits, RuleHit{
				RuleName:    rule.Name,
				Engine:      "sigma-external",
				Description: rule.Description,
				Severity:    rule.Severity,
				MITRETTP:    rule.MITRETTP,
				MatchedOn:   fmt.Sprintf("PID %d EventType:%s", ev.PID, ev.EventType),
				Evidence:    fmt.Sprintf("External Sigma rule matched event data"),
			})
		}
	}
	return hits
}

// ─── Scope matching ──────────────────────────────────────────────────────────

// logsource category → monitor categories/event-types mapping
var logsourceCategoryMap = map[string][]string{
	"process_creation":    {monitor.CatProcess, monitor.EventProcessCreate},
	"process":             {monitor.CatProcess},
	"file_event":          {monitor.CatFile, monitor.EventFileWrite},
	"file_change":         {monitor.CatFile, monitor.EventFileWrite},
	"registry_event":      {monitor.CatRegistry, monitor.EventRegSet},
	"registry_add":        {monitor.CatRegistry, monitor.EventRegSet},
	"registry_set":        {monitor.CatRegistry, monitor.EventRegSet},
	"network_connection":  {monitor.CatNetwork, monitor.EventNetConnect},
	"dns_query":           {monitor.CatNetwork, monitor.EventNetDNS},
	"ps_script":           {monitor.CatScript, monitor.EventPowerShell},
	"powershell":          {monitor.CatScript, monitor.EventPowerShell},
	"create_remote_thread":{monitor.CatAPI, monitor.EventThreadCreate},
	"image_load":          {monitor.CatMemory, monitor.EventImageLoad},
}

func (r *compiledSigmaRule) matchesEventScope(ev monitor.Event) bool {
	if len(r.targetCategories) == 0 && len(r.targetEventTypes) == 0 {
		return true // no scope restriction
	}
	for _, c := range r.targetCategories {
		if ev.Category == c || ev.EventType == c {
			return true
		}
	}
	for _, t := range r.targetEventTypes {
		if ev.EventType == t {
			return true
		}
	}
	return false
}

// ─── Runtime matching ─────────────────────────────────────────────────────────

func (r *compiledSigmaRule) matches(ev monitor.Event) bool {
	// Keyword rules: search the serialised event data string
	if len(r.keywords) > 0 {
		serialised := strings.ToLower(flattenEventData(ev))
		matched := 0
		for _, kw := range r.keywords {
			if strings.Contains(serialised, strings.ToLower(kw)) {
				matched++
			}
		}
		if r.conditionAny && matched > 0 {
			return true
		}
		if !r.conditionAny && matched == len(r.keywords) {
			return true
		}
	}

	if len(r.selectors) == 0 {
		return false
	}

	matchedSelectors := 0
	for _, sel := range r.selectors {
		if selectorMatches(sel, ev) {
			matchedSelectors++
		}
	}

	if r.conditionAny {
		return matchedSelectors > 0
	}
	return matchedSelectors == len(r.selectors)
}

func selectorMatches(sel sigmaSelector, ev monitor.Event) bool {
	for field, accepted := range sel.fields {
		val := extractField(field, ev)
		if val == "" {
			return false
		}
		lval := strings.ToLower(val)
		matched := false
		for _, a := range accepted {
			pattern := strings.ToLower(a)
			// Support '*' wildcard prefix/suffix
			if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
				if strings.Contains(lval, strings.Trim(pattern, "*")) {
					matched = true
					break
				}
			} else if strings.HasPrefix(pattern, "*") {
				if strings.HasSuffix(lval, strings.TrimPrefix(pattern, "*")) {
					matched = true
					break
				}
			} else if strings.HasSuffix(pattern, "*") {
				if strings.HasPrefix(lval, strings.TrimSuffix(pattern, "*")) {
					matched = true
					break
				}
			} else {
				if lval == pattern || strings.Contains(lval, pattern) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// extractField maps Sigma field names to monitor.Event data keys.
func extractField(field string, ev monitor.Event) string {
	lf := strings.ToLower(field)
	// Direct data map lookup first (most common)
	for k, v := range ev.Data {
		if strings.ToLower(k) == lf {
			return fmt.Sprintf("%v", v)
		}
	}
	// Aliased fields
	aliases := map[string]string{
		"commandline":   "cmdline",
		"image":         "image_path",
		"parentimage":   "parent_image",
		"targetfilename":"path",
		"targetobject":  "key",
		"details":       "value_data",
		"query":         "dns_query",
		"destination.ip": "dest_ip",
		"destination.port": "dest_port",
		"scriptblocktext": "script_block",
		"objectname":    "object_name",
		"objecttype":    "object_type",
	}
	if mapped, ok := aliases[lf]; ok {
		for k, v := range ev.Data {
			if strings.ToLower(k) == mapped {
				return fmt.Sprintf("%v", v)
			}
		}
	}
	// Top-level event fields
	switch lf {
	case "pid":
		return fmt.Sprintf("%d", ev.PID)
	case "eventtype", "event_type":
		return ev.EventType
	case "category":
		return ev.Category
	}
	return ""
}

func flattenEventData(ev monitor.Event) string {
	var sb strings.Builder
	for _, v := range ev.Data {
		sb.WriteString(fmt.Sprintf("%v ", v))
	}
	return sb.String()
}

// ─── Parser ───────────────────────────────────────────────────────────────────

func parseSigmaFile(path string) (*compiledSigmaRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sigma_loader: read %s: %w", path, err)
	}

	var raw sigmaRuleFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("sigma_loader: parse %s: %w", path, err)
	}

	// Require at minimum a title and detection block
	if raw.Title == "" || raw.Detection == nil {
		return nil, nil // not a valid Sigma rule, skip silently
	}

	rule := &compiledSigmaRule{
		Name:         raw.Title,
		Description:  raw.Description,
		Severity:     normaliseSeverity(raw.Level),
		conditionAny: true, // default
	}

	// Extract MITRE technique from tags (attack.tXXXX)
	for _, tag := range raw.Tags {
		lower := strings.ToLower(tag)
		if strings.HasPrefix(lower, "attack.t") {
			ttp := strings.ToUpper(strings.TrimPrefix(lower, "attack."))
			// First match wins
			if rule.MITRETTP == "" {
				rule.MITRETTP = ttp
			}
		}
	}

	// Logsource → target event categories
	if cat, ok := logsourceCategoryMap[strings.ToLower(raw.Logsource.Category)]; ok {
		for _, c := range cat {
			if strings.Contains(c, "_") && !strings.Contains(c, "network") {
				rule.targetEventTypes = append(rule.targetEventTypes, c)
			} else {
				rule.targetCategories = append(rule.targetCategories, c)
			}
		}
	}
	// product-level fallback
	if strings.ToLower(raw.Logsource.Product) == "windows" && len(rule.targetCategories) == 0 {
		rule.targetCategories = []string{monitor.CatProcess, monitor.CatAPI, monitor.CatRegistry}
	}

	// Parse detection block
	condition, hasCondition := raw.Detection["condition"]
	condStr := ""
	if hasCondition {
		condStr = strings.ToLower(fmt.Sprintf("%v", condition))
	}

	// Keyword detection block
	if kwRaw, ok := raw.Detection["keywords"]; ok {
		switch kw := kwRaw.(type) {
		case []interface{}:
			for _, k := range kw {
				rule.keywords = append(rule.keywords, fmt.Sprintf("%v", k))
			}
		case string:
			rule.keywords = append(rule.keywords, kw)
		}
		rule.conditionAny = !strings.Contains(condStr, "all of")
		return rule, nil
	}

	// Named selection blocks
	for key, val := range raw.Detection {
		if key == "condition" {
			continue
		}
		sel, err := compileSelector(key, val)
		if err != nil {
			continue
		}
		rule.selectors = append(rule.selectors, sel)
	}

	// Parse condition
	if condStr != "" {
		if strings.Contains(condStr, "all of") {
			rule.conditionAny = false
		} else {
			rule.conditionAny = true
		}
	}

	return rule, nil
}

func compileSelector(name string, raw interface{}) (sigmaSelector, error) {
	sel := sigmaSelector{
		name:   name,
		fields: make(map[string][]string),
	}

	switch v := raw.(type) {
	case map[string]interface{}:
		for field, valRaw := range v {
			// Strip Sigma modifiers (|contains, |startswith, etc.) — keep field name only
			fieldName := strings.SplitN(field, "|", 2)[0]
			var values []string
			switch vals := valRaw.(type) {
			case []interface{}:
				for _, item := range vals {
					values = append(values, fmt.Sprintf("%v", item))
				}
			case string:
				values = append(values, vals)
			case interface{}:
				values = append(values, fmt.Sprintf("%v", vals))
			}
			// Attach wildcard for |contains modifier
			if strings.Contains(field, "|contains") {
				for i, val := range values {
					if !strings.HasPrefix(val, "*") {
						values[i] = "*" + val + "*"
					}
				}
			} else if strings.Contains(field, "|startswith") {
				for i, val := range values {
					if !strings.HasSuffix(val, "*") {
						values[i] = val + "*"
					}
				}
			} else if strings.Contains(field, "|endswith") {
				for i, val := range values {
					if !strings.HasPrefix(val, "*") {
						values[i] = "*" + val
					}
				}
			}
			sel.fields[fieldName] = values
		}
	case []interface{}:
		// flat value list without field names → keyword-style, search all data
		sel.fields["_any"] = nil
		for _, item := range v {
			sel.fields["_any"] = append(sel.fields["_any"], fmt.Sprintf("%v", item))
		}
	default:
		return sel, fmt.Errorf("unrecognised selector type for %s", name)
	}

	return sel, nil
}
