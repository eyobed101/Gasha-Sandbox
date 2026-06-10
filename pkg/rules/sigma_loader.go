package rules

// sigma_loader.go — loads standard Sigma rule files (.yml) and compiles them
// into runtime detectors.
//
// Condition expression support:
//   selection                     single named block must match
//   selection1 and selection2     both must match
//   selection1 or  selection2     either must match
//   not filter                    filter block must NOT match
//   1 of selection_*              at least 1 of wildcard-named blocks
//   all of selection_*            all wildcard-named blocks
//   N of selection_*              at least N
//   all of keywords               every keyword present
//   1 of keywords                 any keyword present
//
// Field modifier support:
//   |contains   |startswith   |endswith   |re   |cidr (skipped gracefully)
//   |contains|all  (all values must appear in the field)
//
// NOT filter: blocks named "filter*" referenced as "not filter*" in the
// condition are evaluated and the rule is suppressed if they match.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lemas-sandbox/lemas/pkg/monitor"
)

// ─── Raw YAML structures ─────────────────────────────────────────────────────

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

// ─── Compiled rule structures ─────────────────────────────────────────────────

type compiledSigmaRule struct {
	Name             string
	Description      string
	Severity         string
	MITRETTP         string
	targetCategories []string
	targetEventTypes []string
	targetEventIDs   []int  // EventID values this rule targets (for index)
	// Named selector blocks indexed by name
	selectorMap map[string]sigmaSelector
	// Keywords block (flat string list)
	keywords     []string
	keywordsAll  bool // true = all must match, false = any
	// Parsed condition expression tree
	condExpr sigmaCondExpr
}

// sigmaSelector is one detection block: field → []matcher
type sigmaSelector struct {
	name   string
	fields []sigmaFieldMatcher
}

// sigmaFieldMatcher matches one field against a set of values/patterns.
type sigmaFieldMatcher struct {
	fieldName  string
	values     []string          // plain/wildcard values
	regexes    []*regexp.Regexp  // compiled |re patterns
	matchAll   bool              // |contains|all — every value must appear
}

// sigmaCondExpr is a node in the boolean condition tree.
type sigmaCondExpr struct {
	op       sigmaOp
	name     string            // for opName / opWildcard
	prefix   string            // for opWildcard: selector name prefix
	minCount int               // for opCount
	left     *sigmaCondExpr
	right    *sigmaCondExpr
}

type sigmaOp uint8

const (
	opName     sigmaOp = iota // reference to a named selector
	opWildcard                // "1 of selection_*" style
	opAnd
	opOr
	opNot
	opKeywords
)

// ExternalSigmaRules is the loaded rule set with a pre-filter index.
type ExternalSigmaRules struct {
	rules []compiledSigmaRule
	// indexByEventType maps EventID → rules that can match that event.
	// Rules without a specific scope match all events.
	indexByEventType map[int][]int // EventID → rule indices
	unscoped         []int         // rule indices with no scope restriction
}

// ─── Logsource mapping ───────────────────────────────────────────────────────

var logsourceCategoryMap = map[string][]string{
	// ── Process ─────────────────────────────────────────────────────────────
	"process_creation":         {monitor.CatProcess, monitor.EventProcessCreate},
	"process":                  {monitor.CatProcess},
	"process_access":           {monitor.CatProcess, monitor.EventProcessAccess},
	"process_termination":      {monitor.CatProcess, monitor.EventProcessExit},
	"process_tampering":        {monitor.CatMemory, monitor.EventThreadCreate},

	// ── File ────────────────────────────────────────────────────────────────
	"file":                     {monitor.CatFile},
	"file_event":               {monitor.CatFile, monitor.EventFileWrite},
	"file_change":              {monitor.CatFile, monitor.EventFileWrite},
	"file_delete":              {monitor.CatFile, monitor.EventFileDelete},
	"file_access":              {monitor.CatFile, monitor.EventFileWrite},
	"file_executable_detected": {monitor.CatFile, monitor.EventFileWrite},
	"file_rename":              {monitor.CatFile, monitor.EventFileWrite},
	"create_stream_hash":       {monitor.CatFile, monitor.EventFileWrite},
	"pipe_created":             {monitor.CatFile, monitor.EventFileWrite},

	// ── Registry ────────────────────────────────────────────────────────────
	"registry":         {monitor.CatRegistry},
	"registry_event":   {monitor.CatRegistry, monitor.EventRegSet},
	"registry_add":     {monitor.CatRegistry, monitor.EventRegSet},
	"registry_set":     {monitor.CatRegistry, monitor.EventRegSet},
	"registry_delete":  {monitor.CatRegistry, monitor.EventRegDelete},

	// ── Network ─────────────────────────────────────────────────────────────
	"network":              {monitor.CatNetwork},
	"network_connection":   {monitor.CatNetwork, monitor.EventNetConnect},
	"dns_query":            {monitor.CatNetwork, monitor.EventNetDNS},
	"dns":                  {monitor.CatNetwork, monitor.EventNetDNS},
	"firewall":             {monitor.CatNetwork},
	"proxy":                {monitor.CatNetwork},
	"webserver":            {monitor.CatNetwork},

	// ── Script / PowerShell ─────────────────────────────────────────────────
	"ps_script":                {monitor.CatScript, monitor.EventPowerShell},
	"ps_module":                {monitor.CatScript, monitor.EventPowerShell},
	"ps_classic_start":         {monitor.CatScript, monitor.EventPowerShell},
	"ps_classic_provider_start": {monitor.CatScript, monitor.EventPowerShell},
	"powershell":               {monitor.CatScript, monitor.EventPowerShell},

	// ── Memory / Image ──────────────────────────────────────────────────────
	"image_load":           {monitor.CatMemory, monitor.EventImageLoad},
	"driver_load":          {monitor.CatMemory, monitor.EventImageLoad},
	"create_remote_thread": {monitor.CatMemory, monitor.EventThreadCreate},
	"raw_access_thread":    {monitor.CatAPI, monitor.EventAPICall},

	// ── Persistence ─────────────────────────────────────────────────────────
	"wmi_event":   {monitor.CatPersistence, monitor.EventWMI},
	"scheduled_task": {monitor.CatPersistence, monitor.EventSchedTask},
	"service_install": {monitor.CatPersistence, monitor.EventServiceInstall},

	// ── System / monitoring infrastructure ─────────────────────────────────
	"sysmon_error":  {monitor.CatAPI},
	"sysmon_status": {monitor.CatAPI},
	"antivirus":     {monitor.CatFile},
	"application":   {monitor.CatAPI},
	"database":      {monitor.CatAPI},

	// ── Product-based (cross-platform / app) ────────────────────────────────
	"windows":    {monitor.CatProcess, monitor.CatAPI, monitor.CatRegistry},
	"linux":      {monitor.CatProcess},
	"macos":      {monitor.CatProcess},
	"zeek":       {monitor.CatNetwork},
	"cisco":      {monitor.CatNetwork},
	"fortigate":  {monitor.CatNetwork},
	"juniper":    {monitor.CatNetwork},
	"huawei":     {monitor.CatNetwork},
	"rpc_firewall": {monitor.CatNetwork},

	// ── Cloud / SaaS ────────────────────────────────────────────────────────
	"aws":        {monitor.CatNetwork},
	"azure":      {monitor.CatNetwork},
	"gcp":        {monitor.CatNetwork},
	"kubernetes": {monitor.CatProcess},
	"okta":       {monitor.CatNetwork},
	"onelogin":   {monitor.CatNetwork},
	"m365":       {monitor.CatNetwork},
	"github":     {monitor.CatNetwork},
	"bitbucket":  {monitor.CatNetwork},

	// ── Web / Application framework ─────────────────────────────────────────
	"django":       {monitor.CatAPI},
	"python":       {monitor.CatScript},
	"ruby_on_rails": {monitor.CatAPI},
	"spring":       {monitor.CatAPI},
	"velocity":     {monitor.CatAPI},
	"nodejs":       {monitor.CatScript},
	"jvm":          {monitor.CatAPI},
	"sql":          {monitor.CatAPI},

	// ── Service-based (Windows Event Log sources) ──────────────────────────
	"security":       {monitor.CatProcess, monitor.CatAPI},
	"system":         {monitor.CatAPI, monitor.CatRegistry},
	"sysmon":         {monitor.CatProcess, monitor.CatFile, monitor.CatRegistry, monitor.CatNetwork, monitor.CatMemory},
	"applocker":      {monitor.CatFile},
	"windefend":      {monitor.CatFile},
	"codeintegrity":  {monitor.CatMemory},
	"bits-client":    {monitor.CatNetwork},
	"dns-server":     {monitor.CatNetwork},
	"dns-client":     {monitor.CatNetwork},
	"taskscheduler":  {monitor.CatPersistence},
	"wmi":            {monitor.CatPersistence},
	"kerberos":       {monitor.CatAPI},
	"ldap":           {monitor.CatAPI},
	"rdp":            {monitor.CatNetwork},
	"smb":            {monitor.CatNetwork},
	"smbclient":      {monitor.CatNetwork},
	"iis":            {monitor.CatNetwork},
	"exchange":       {monitor.CatAPI},
	"nginx":          {monitor.CatNetwork},
	"apache":         {monitor.CatNetwork},
	"openssh":        {monitor.CatProcess},
	"sshd":           {monitor.CatProcess},
	"ftp":            {monitor.CatNetwork},
	"dhcp":           {monitor.CatNetwork},
	"ntlm":           {monitor.CatAPI},
}

// ─── Public API ──────────────────────────────────────────────────────────────

func LoadSigmaRules(dir string) (*ExternalSigmaRules, []error) {
	var out ExternalSigmaRules
	var errs []error

	if dir == "" {
		return &out, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return &out, nil
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		lower := strings.ToLower(e.Name())
		if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
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
	out.buildIndex()
	return &out, errs
}

// buildIndex populates the pre-filter index for faster evaluation.
func (es *ExternalSigmaRules) buildIndex() {
	es.indexByEventType = make(map[int][]int)
	for idx, rule := range es.rules {
		if len(rule.targetEventIDs) == 0 && len(rule.targetCategories) == 0 && len(rule.targetEventTypes) == 0 {
			es.unscoped = append(es.unscoped, idx)
			continue
		}
		if len(rule.targetEventIDs) > 0 {
			for _, eid := range rule.targetEventIDs {
				es.indexByEventType[eid] = append(es.indexByEventType[eid], idx)
			}
		}
	}
}

// Evaluate runs all loaded external Sigma rules against a single event.
// Uses the pre-filter index to skip scoped rules that can't match this event.
func (es *ExternalSigmaRules) Evaluate(ev monitor.Event) []RuleHit {
	var hits []RuleHit

	// Collect candidate rule indices from the index
	candidates := make(map[int]bool)

	// Unscoped rules (no logsource) always run
	for _, idx := range es.unscoped {
		candidates[idx] = true
	}

	// EventID-indexed rules
	if ev.EventID > 0 {
		for _, idx := range es.indexByEventType[ev.EventID] {
			candidates[idx] = true
		}
	}

	// Rules that match by scope but weren't in the EventID index
	for idx, rule := range es.rules {
		if candidates[idx] {
			continue
		}
		if rule.matchesScope(ev) {
			candidates[idx] = true
		}
	}

	for idx := range candidates {
		rule := es.rules[idx]
		if rule.matches(ev) {
			hits = append(hits, RuleHit{
				RuleName:    rule.Name,
				Engine:      "sigma-external",
				Description: rule.Description,
				Severity:    rule.Severity,
				MITRETTP:    rule.MITRETTP,
				MatchedOn:   fmt.Sprintf("PID %d EventType:%s", ev.PID, ev.EventType),
				Evidence:    "External Sigma rule matched event data",
			})
		}
	}
	return hits
}

// ─── Scope check ─────────────────────────────────────────────────────────────

func (r *compiledSigmaRule) matchesScope(ev monitor.Event) bool {
	if len(r.targetCategories) == 0 && len(r.targetEventTypes) == 0 && len(r.targetEventIDs) == 0 {
		return true
	}
	for _, eid := range r.targetEventIDs {
		if ev.EventID == eid {
			return true
		}
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

// ─── Runtime matching ────────────────────────────────────────────────────────

func (r *compiledSigmaRule) matches(ev monitor.Event) bool {
	return evalCondExpr(&r.condExpr, r, ev)
}

func evalCondExpr(expr *sigmaCondExpr, rule *compiledSigmaRule, ev monitor.Event) bool {
	// Iterative evaluation using an explicit stack to avoid stack overflow on
	// deep OR-chains built by chainConditions over many selectors.
	type frame struct {
		expr   *sigmaCondExpr
		result *bool // where to write result when done
	}
	// We implement a simple recursive descent but with a depth guard.
	return evalExprDepth(expr, rule, ev, 0)
}

const maxExprDepth = 64

func evalExprDepth(expr *sigmaCondExpr, rule *compiledSigmaRule, ev monitor.Event, depth int) bool {
	if expr == nil || depth > maxExprDepth {
		return false
	}
	switch expr.op {
	case opName:
		if expr.name == "" {
			return false
		}
		sel, ok := rule.selectorMap[expr.name]
		if !ok {
			return false
		}
		return selectorMatchesEvent(sel, ev)

	case opKeywords:
		return evalKeywords(rule, ev)

	case opWildcard:
		count := 0
		for name, sel := range rule.selectorMap {
			if strings.HasPrefix(name, expr.prefix) {
				if selectorMatchesEvent(sel, ev) {
					count++
				}
			}
		}
		return count >= expr.minCount

	case opAnd:
		return evalExprDepth(expr.left, rule, ev, depth+1) &&
			evalExprDepth(expr.right, rule, ev, depth+1)

	case opOr:
		return evalExprDepth(expr.left, rule, ev, depth+1) ||
			evalExprDepth(expr.right, rule, ev, depth+1)

	case opNot:
		return !evalExprDepth(expr.left, rule, ev, depth+1)
	}
	return false
}

func evalKeywords(rule *compiledSigmaRule, ev monitor.Event) bool {
	serialised := strings.ToLower(flattenEventData(ev))
	matched := 0
	for _, kw := range rule.keywords {
		if strings.Contains(serialised, strings.ToLower(kw)) {
			matched++
		}
	}
	if rule.keywordsAll {
		return matched == len(rule.keywords)
	}
	return matched > 0
}

func selectorMatchesEvent(sel sigmaSelector, ev monitor.Event) bool {
	for _, fm := range sel.fields {
		if !fieldMatcherMatches(fm, ev) {
			return false
		}
	}
	return len(sel.fields) > 0
}

func fieldMatcherMatches(fm sigmaFieldMatcher, ev monitor.Event) bool {
	val := extractField(fm.fieldName, ev)
	if val == "" {
		return false
	}
	lval := strings.ToLower(val)

	// Regex patterns
	for _, re := range fm.regexes {
		if re.MatchString(val) {
			return true
		}
	}

	if fm.matchAll {
		// Every value must be found in the field
		for _, pattern := range fm.values {
			if !wildcardMatch(lval, strings.ToLower(pattern)) {
				return false
			}
		}
		return len(fm.values) > 0
	}

	// Any value matches
	for _, pattern := range fm.values {
		if wildcardMatch(lval, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// wildcardMatch supports leading/trailing * as wildcards.
func wildcardMatch(s, pattern string) bool {
	hasPrefix := strings.HasPrefix(pattern, "*")
	hasSuffix := strings.HasSuffix(pattern, "*")
	core := strings.Trim(pattern, "*")

	if hasPrefix && hasSuffix {
		return strings.Contains(s, core)
	}
	if hasPrefix {
		return strings.HasSuffix(s, core)
	}
	if hasSuffix {
		return strings.HasPrefix(s, core)
	}
	return s == pattern || strings.Contains(s, pattern)
}

// extractField resolves a Sigma field name to a value from the event.
func extractField(field string, ev monitor.Event) string {
	lf := strings.ToLower(field)
	for k, v := range ev.Data {
		if strings.ToLower(k) == lf {
			return fmt.Sprintf("%v", v)
		}
	}
	// Common Sigma → internal field aliases
	aliases := map[string]string{
		"commandline":          "cmdline",
		"image":                "image_path",
		"parentimage":          "parent_image",
		"parentcommandline":    "parent_cmdline",
		"targetfilename":       "path",
		"targetobject":         "key",
		"details":              "value_data",
		"query":                "dns_query",
		"destination.ip":       "dest_ip",
		"destination.port":     "dest_port",
		"destinationip":        "dest_ip",
		"destinationport":      "dest_port",
		"destinationhostname":  "domain",
		"sourceip":             "src_ip",
		"sourceport":           "src_port",
		"scriptblocktext":      "script_block",
		"objectname":           "object_name",
		"objecttype":           "object_type",
		"sha256":               "sha256",
		"md5":                  "md5",
		"hashes":               "sha256",
		"integritylevel":       "integrity_level",
		"user":                 "user",
		"imageloaded":          "image_name",
		"queryname":            "dns_query",
		"originalfilename":     "original_filename",
		"processguid":          "process_guid",
		"parentprocessguid":    "parent_process_guid",
		"logonid":              "logon_id",
		"sourceimage":          "source_image",
		"targetimage":          "target_image",
		"servicefilename":      "service_file",
		"servicename":          "service_name",
		"taskname":             "task_name",
		"usercontext":          "user_context",
		"wmi_query":            "wmi_query",
		"wmi_consumer":         "wmi_consumer",
		"grantedaccess":        "access_mask",
		"calltrace":            "call_stack",
		"initiated":            "outbound",
		"imagepath":            "service_imagepath",
		"imphash":              "imphash",
	}
	if mapped, ok := aliases[lf]; ok {
		for k, v := range ev.Data {
			if strings.ToLower(k) == mapped {
				return fmt.Sprintf("%v", v)
			}
		}
	}
	switch lf {
	case "eventid", "event_id":
		if ev.EventID > 0 {
			return fmt.Sprintf("%d", ev.EventID)
		}
		return ""
	case "pid":
		return fmt.Sprintf("%d", ev.PID)
	case "event_type", "eventtype":
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

	if raw.Title == "" || raw.Detection == nil {
		return nil, nil // not a Sigma rule
	}

	rule := &compiledSigmaRule{
		Name:        raw.Title,
		Description: raw.Description,
		Severity:    normaliseSeverity(raw.Level),
		selectorMap: make(map[string]sigmaSelector),
	}

	// Extract MITRE TTP from tags
	for _, tag := range raw.Tags {
		lower := strings.ToLower(tag)
		if strings.HasPrefix(lower, "attack.t") {
			ttp := strings.ToUpper(strings.TrimPrefix(lower, "attack."))
			if rule.MITRETTP == "" {
				rule.MITRETTP = ttp
			}
		}
	}

	// Map logsource category to event scope
	applyLogsource(rule, raw.Logsource)

	// Extract condition string
	condRaw, _ := raw.Detection["condition"]
	condStr := strings.TrimSpace(fmt.Sprintf("%v", condRaw))

	// Parse keywords block
	if kwRaw, ok := raw.Detection["keywords"]; ok {
		switch kw := kwRaw.(type) {
		case []interface{}:
			for _, k := range kw {
				rule.keywords = append(rule.keywords, fmt.Sprintf("%v", k))
			}
		case string:
			rule.keywords = append(rule.keywords, kw)
		}
		lowerCond := strings.ToLower(condStr)
		rule.keywordsAll = strings.Contains(lowerCond, "all of keywords") ||
			strings.Contains(lowerCond, "all of")
	}

	// Parse all named selection blocks
	for key, val := range raw.Detection {
		if key == "condition" || key == "keywords" {
			continue
		}
		sel, err := compileSelector(key, val)
		if err != nil {
			continue
		}
		rule.selectorMap[key] = sel
	}

	// Parse condition expression
	rule.condExpr = parseCondExpr(condStr, rule)

	return rule, nil
}

var logsourceEventIDMap = map[string][]int{
	// ── Sysmon EventIDs ─────────────────────────────────────────────────────
	"process_creation":          {1},
	"process_termination":       {5},
	"process_access":            {10},
	"network_connection":        {3},
	"dns_query":                 {22},
	"dns":                       {22},
	"file_event":                {11},
	"file_delete":               {23},
	"file_rename":               {2},
	"file_change":               {11},
	"file_executable_detected":  {29},
	"create_stream_hash":        {15},
	"registry_set":              {13},
	"registry_delete":           {14},
	"image_load":                {7},
	"create_remote_thread":      {8},
	"driver_load":               {7},
	"pipe_created":              {17},
	"raw_access_thread":         {24},
	"process_tampering":         {8},

	// ── Windows Event Log common EventIDs ──────────────────────────────────
	"wmi_event":                 {5860, 5861, 11},
	"scheduled_task":            {106, 140, 200, 141},
	"service_install":           {7045, 4697},
	"powershell":                {4104, 4103},
	"ps_script":                 {4104, 4103},
	"ps_module":                 {4103},
	"ps_classic_start":          {400, 600},
	"ps_classic_provider_start": {400, 600},
	"sysmon_error":              {255},
	"sysmon_status":             {4},

	// ── Security audit most-used EventIDs ──────────────────────────────────
	"security": {4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4702, 4719,
		4720, 4728, 4732, 4735, 4740, 4754, 4768, 4769, 4771, 4776,
		4778, 4779, 4781, 4793, 4798, 4799, 4800, 4801, 4802, 4803,
		4868, 4870, 4872, 4874, 4876, 4882, 4883, 4898, 4902, 4907,
		4908, 4910, 4912, 4913, 4928, 4929, 4930, 4931, 4932, 4933,
		4944, 4946, 4947, 4948, 4951, 4953, 4954, 4956, 4957, 4958,
		4960, 4964, 4971, 4974, 4976, 4977, 4978, 4979, 4983, 4984,
		4985, 5027, 5028, 5029, 5030, 5031, 5032, 5033, 5034, 5035,
		5037, 5038, 5039, 5040, 5041, 5049, 5050, 5051, 5052, 5056,
		5057, 5058, 5059, 5060, 5061, 5062, 5063, 5064, 5065, 5066,
		5067, 5068, 5069, 5070, 5071, 5072, 5073, 5074, 5075, 5076,
		5077, 5078, 5079, 5080, 5081, 5082, 5083, 5084, 5085, 5086,
		5087, 5088, 5089, 5090, 5091, 5092, 5093, 5094, 5095, 5096,
		5097, 5098, 5099, 5100, 5101, 5102, 5103, 5104, 5105, 5106,
		5107, 5136, 5137, 5138, 5139, 5140, 5141, 5142, 5143, 5144,
		5145, 5146, 5147, 5148, 5149, 5150, 5151, 5152, 5153, 5154,
		5155, 5156, 5157, 5158, 5159, 5160, 5161, 5162, 5163, 5164,
		5165, 5166, 5167, 5168, 5169, 5170, 5171, 5172, 5173, 5174,
		5175, 5176, 5177, 5178, 5179, 5180, 5181, 5182, 5183, 5184,
		5185, 5186, 5187, 5188, 5189, 5190, 5191, 5192, 5193, 5194,
		5195, 5196, 5197, 5198, 5199, 5200, 5201, 5202, 5203, 5377,
		5378, 5379, 5380, 5381, 5382, 5440, 5442, 5444, 5446, 5447,
		5449, 5450, 5451, 5452, 5453, 5454, 5455, 5456, 5457, 5458,
		5459, 5460, 5461, 5462, 5463, 5464, 5465, 5466, 5467, 5468,
		5469, 5470, 5471, 5472, 5473, 5474, 5475, 5476, 5477, 5478,
		5480, 5481, 5482, 5483, 5484, 5485, 6144, 6145, 6272, 6273,
		6274, 6275, 6276, 6277, 6278},

	// ── System log common EventIDs ─────────────────────────────────────────
	"system": {7030, 7031, 7032, 7034, 7036, 7040, 7045, 7049},
}

func applyLogsource(rule *compiledSigmaRule, ls sigmaLogsource) {
	if eids, ok := logsourceEventIDMap[strings.ToLower(ls.Category)]; ok {
		rule.targetEventIDs = append(rule.targetEventIDs, eids...)
	}
	if mappings, ok := logsourceCategoryMap[strings.ToLower(ls.Category)]; ok {
		for _, m := range mappings {
			// Heuristic: event type constants contain "_" and are not pure category names
			if strings.ContainsAny(m, "_") && m != monitor.CatNetwork && m != monitor.CatProcess &&
				m != monitor.CatFile && m != monitor.CatRegistry && m != monitor.CatAPI &&
				m != monitor.CatMemory && m != monitor.CatScript {
				rule.targetEventTypes = append(rule.targetEventTypes, m)
			} else {
				rule.targetCategories = append(rule.targetCategories, m)
			}
		}
	}
	if strings.ToLower(ls.Product) == "windows" && len(rule.targetCategories) == 0 && len(rule.targetEventTypes) == 0 {
		rule.targetCategories = []string{monitor.CatProcess, monitor.CatAPI, monitor.CatRegistry}
	}
}

// ─── Condition expression parser ─────────────────────────────────────────────
//
// Grammar (simplified, left-to-right precedence: NOT > AND > OR):
//   expr  = term (OR term)*
//   term  = factor (AND factor)*
//   factor = NOT factor | atom
//   atom  = '(' expr ')' | quantifier | name
//   quantifier = (N|"all"|"any"|"1") "of" (name | "them" | wildcard)

func parseCondExpr(cond string, rule *compiledSigmaRule) sigmaCondExpr {
	tokens := tokeniseCond(cond)
	if len(tokens) == 0 {
		// Default: OR all non-filter selectors
		return defaultCondExpr(rule)
	}
	expr, _ := parseOrExpr(tokens, 0, rule)
	return expr
}

func parseOrExpr(tokens []string, pos int, rule *compiledSigmaRule) (sigmaCondExpr, int) {
	left, pos := parseAndExpr(tokens, pos, rule)
	for pos < len(tokens) && strings.ToLower(tokens[pos]) == "or" {
		pos++
		right, newPos := parseAndExpr(tokens, pos, rule)
		pos = newPos
		l, r := left, right
		left = sigmaCondExpr{op: opOr, left: &l, right: &r}
	}
	return left, pos
}

func parseAndExpr(tokens []string, pos int, rule *compiledSigmaRule) (sigmaCondExpr, int) {
	left, pos := parseNotExpr(tokens, pos, rule)
	for pos < len(tokens) && strings.ToLower(tokens[pos]) == "and" {
		pos++
		right, newPos := parseNotExpr(tokens, pos, rule)
		pos = newPos
		l, r := left, right
		left = sigmaCondExpr{op: opAnd, left: &l, right: &r}
	}
	return left, pos
}

func parseNotExpr(tokens []string, pos int, rule *compiledSigmaRule) (sigmaCondExpr, int) {
	if pos < len(tokens) && strings.ToLower(tokens[pos]) == "not" {
		pos++
		inner, newPos := parseNotExpr(tokens, pos, rule)
		i := inner
		return sigmaCondExpr{op: opNot, left: &i}, newPos
	}
	return parseAtom(tokens, pos, rule)
}

func parseAtom(tokens []string, pos int, rule *compiledSigmaRule) (sigmaCondExpr, int) {
	if pos >= len(tokens) {
		return sigmaCondExpr{op: opName, name: ""}, pos
	}

	tok := tokens[pos]

	// Parenthesised sub-expression
	if tok == "(" {
		pos++
		expr, newPos := parseOrExpr(tokens, pos, rule)
		if newPos < len(tokens) && tokens[newPos] == ")" {
			newPos++
		}
		return expr, newPos
	}

	lTok := strings.ToLower(tok)

	// Quantifier: "1 of ...", "all of ...", "any of ...", "N of ..."
	isQuant := lTok == "all" || lTok == "any" || lTok == "1"
	if !isQuant {
		if _, err := fmt.Sscanf(lTok, "%d", new(int)); err == nil {
			isQuant = true
		}
	}
	if isQuant && pos+2 < len(tokens) && strings.ToLower(tokens[pos+1]) == "of" {
		return parseQuantifier(tokens, pos, rule)
	}

	// keywords reference
	if lTok == "keywords" {
		return sigmaCondExpr{op: opKeywords}, pos + 1
	}

	// Named selector reference (possibly with wildcard suffix in the name)
	return sigmaCondExpr{op: opName, name: tok}, pos + 1
}

func parseQuantifier(tokens []string, pos int, rule *compiledSigmaRule) (sigmaCondExpr, int) {
	quantTok := strings.ToLower(tokens[pos])
	pos += 2 // skip "N of"

	var minCount int
	switch quantTok {
	case "all":
		minCount = -1 // special: all
	case "any":
		minCount = 1
	default:
		fmt.Sscanf(quantTok, "%d", &minCount)
		if minCount == 0 {
			minCount = 1
		}
	}

	if pos >= len(tokens) {
		return defaultCondExpr(rule), pos
	}

	target := tokens[pos]
	pos++
	lTarget := strings.ToLower(target)

	// "all of them" / "any of them" — applies to all selectors
	if lTarget == "them" {
		if minCount == -1 {
			expr := buildAllOf(rule)
			return expr, pos
		}
		expr := buildAnyOf(rule)
		return expr, pos
	}

	// "all of keywords"
	if lTarget == "keywords" {
		rule.keywordsAll = (minCount == -1)
		return sigmaCondExpr{op: opKeywords}, pos
	}

	// Wildcard selector name: "1 of selection_*"
	prefix := strings.TrimSuffix(target, "*")
	if strings.HasSuffix(target, "*") {
		actualMin := minCount
		if actualMin == -1 {
			// count matching selectors for "all of"
			count := 0
			for name := range rule.selectorMap {
				if strings.HasPrefix(name, prefix) {
					count++
				}
			}
			actualMin = count
		}
		return sigmaCondExpr{op: opWildcard, prefix: prefix, minCount: actualMin}, pos
	}

	// Plain name
	return sigmaCondExpr{op: opName, name: target}, pos
}

func defaultCondExpr(rule *compiledSigmaRule) sigmaCondExpr {
	return buildAnyOf(rule)
}

func buildAnyOf(rule *compiledSigmaRule) sigmaCondExpr {
	// Use opWildcard with empty prefix to match all non-filter selectors
	return sigmaCondExpr{op: opWildcard, prefix: "selection", minCount: 1}
}

func buildAllOf(rule *compiledSigmaRule) sigmaCondExpr {
	count := 0
	for name := range rule.selectorMap {
		if strings.HasPrefix(name, "selection") {
			count++
		}
	}
	if count == 0 {
		count = len(rule.selectorMap)
		return sigmaCondExpr{op: opWildcard, prefix: "", minCount: count}
	}
	return sigmaCondExpr{op: opWildcard, prefix: "selection", minCount: count}
}

func chainConditions(names []string, op sigmaOp) sigmaCondExpr {
	if len(names) == 0 {
		return sigmaCondExpr{op: opName, name: ""}
	}
	if len(names) == 1 {
		return sigmaCondExpr{op: opName, name: names[0]}
	}
	// Build flat OR/AND using opWildcard isn't possible here without a prefix,
	// so we keep a shallow 2-level tree: evaluate all names iteratively in opWildcard.
	// For named selectors without a common prefix we fall back to a 2-level AND/OR.
	left := sigmaCondExpr{op: opName, name: names[0]}
	for _, name := range names[1:] {
		right := sigmaCondExpr{op: opName, name: name}
		newNode := sigmaCondExpr{op: op, left: &left, right: &right}
		left = newNode
	}
	return left
}

func tokeniseCond(cond string) []string {
	// Insert spaces around parens then split
	cond = strings.ReplaceAll(cond, "(", " ( ")
	cond = strings.ReplaceAll(cond, ")", " ) ")
	var tokens []string
	for _, t := range strings.Fields(cond) {
		if t != "" {
			tokens = append(tokens, t)
		}
	}
	return tokens
}

// ─── Selector compiler ────────────────────────────────────────────────────────

func compileSelector(name string, raw interface{}) (sigmaSelector, error) {
	sel := sigmaSelector{name: name}

	switch v := raw.(type) {
	case map[string]interface{}:
		for fieldSpec, valRaw := range v {
			fm, err := compileFieldMatcher(fieldSpec, valRaw)
			if err != nil {
				continue
			}
			sel.fields = append(sel.fields, fm)
		}
	case []interface{}:
		// Flat list → match any data field
		fm := sigmaFieldMatcher{fieldName: "_any"}
		for _, item := range v {
			fm.values = append(fm.values, fmt.Sprintf("%v", item))
		}
		sel.fields = append(sel.fields, fm)
	default:
		return sel, fmt.Errorf("unsupported selector type for %s", name)
	}
	return sel, nil
}

func compileFieldMatcher(fieldSpec string, valRaw interface{}) (sigmaFieldMatcher, error) {
	parts := strings.Split(fieldSpec, "|")
	fieldName := parts[0]
	modifiers := parts[1:]

	fm := sigmaFieldMatcher{fieldName: fieldName}

	// Collect raw values
	var rawValues []string
	switch vals := valRaw.(type) {
	case []interface{}:
		for _, item := range vals {
			rawValues = append(rawValues, fmt.Sprintf("%v", item))
		}
	case string:
		rawValues = append(rawValues, vals)
	case nil:
		rawValues = append(rawValues, "")
	default:
		rawValues = append(rawValues, fmt.Sprintf("%v", vals))
	}

	// Apply modifiers
	hasContainsAll := false
	for _, mod := range modifiers {
		switch strings.ToLower(mod) {
		case "contains":
			// wrap with * both sides
			for i, v := range rawValues {
				if !strings.HasPrefix(v, "*") {
					rawValues[i] = "*" + v + "*"
				}
			}
		case "startswith":
			for i, v := range rawValues {
				rawValues[i] = v + "*"
			}
		case "endswith":
			for i, v := range rawValues {
				rawValues[i] = "*" + v
			}
		case "all":
			hasContainsAll = true
		case "re":
			// Compile as regex
			for _, v := range rawValues {
				re, err := regexp.Compile("(?i)" + v)
				if err == nil {
					fm.regexes = append(fm.regexes, re)
				}
			}
			return fm, nil // regex matcher — no plain values
		case "cidr":
			// CIDR matching not supported; skip silently
			return fm, fmt.Errorf("cidr modifier not supported")
		}
	}

	fm.values = rawValues
	fm.matchAll = hasContainsAll
	return fm, nil
}

// selectorMatches kept for backward compatibility with tests using the old name
func selectorMatches(sel sigmaSelector, ev monitor.Event) bool {
	return selectorMatchesEvent(sel, ev)
}
