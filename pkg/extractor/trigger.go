// trigger.go — bridges the YARA rule engine with the config extractor registry.
//
// When a YARA rule fires on a file or memory dump, the rule's meta section
// may contain a "lemas_family" field that names the malware family:
//
//   meta:
//       lemas_family = "CobaltStrike Payload"
//       description  = "Cobalt Strike beacon shellcode"
//       severity     = "critical"
//
// The trigger layer:
//   1. Reads the lemas_family meta value from each YARA hit
//   2. Strips the trailing qualifier ( Payload / Config / Loader / Strings)
//   3. Looks up the family name in the extractor registry
//   4. Runs the matching parser against the file/memory bytes
//   5. Returns an ExtractResult with the parsed config + the triggering hit
//
// This mirrors objects.get_cape_name_from_yara_hit() and the
// static_extraction() → static_config_parsers() call chain in CAPEv2,
// using our own naming convention throughout.
package extractor

import (
	"regexp"
	"strings"

	"github.com/lemas-sandbox/lemas/pkg/logger"
)

var triggerLog = logger.ForComponent("extractor-trigger")

// familyQualifierRE strips " Payload", " Config", " Loader", " Strings"
// (case-insensitive) from the end of a lemas_family meta value.
// e.g. "CobaltStrike Payload" → "CobaltStrike"
var familyQualifierRE = regexp.MustCompile(`(?i)\s+(payload|config|loader|strings)$`)

// YARAHit is a normalised YARA rule match — mirrors the dict returned by
// pkg/rules ExternalYaraRules.MatchFile(). We use this subset here to avoid
// a circular import between extractor and rules packages.
type YARAHit struct {
	RuleName string
	Meta     map[string]string // all meta key=value pairs from the rule
	MatchedOn string           // file path or "PID X @ 0xADDR"
}

// ExtractResult bundles a parsed config with the YARA hit that triggered it.
type ExtractResult struct {
	Config   *Config
	FamilyID string  // normalised family name (after qualifier strip)
	HitName  string  // original YARA rule name
	Source   string  // "static_file" | "memory_dump" | "pe_section"
}

// FamilyFromHit extracts the normalised family name from a YARA hit's meta.
// Returns "" if the hit has no lemas_family meta or after stripping the
// qualifier the result is empty.
func FamilyFromHit(hit YARAHit) string {
	raw, ok := hit.Meta["lemas_family"]
	if !ok || raw == "" {
		return ""
	}
	// Strip qualifier suffix
	clean := familyQualifierRE.ReplaceAllString(strings.TrimSpace(raw), "")
	return strings.TrimSpace(clean)
}

// RunOnHits iterates YARA hits, extracts family names, and dispatches parsers.
// data is the raw bytes of the scanned object (file content or memory region).
// source describes where the bytes came from ("static_file", "memory_dump", ...).
//
// Only hits that have a lemas_family meta field and a registered parser are
// processed. The first successful config extraction is returned (mirrors
// CAPEv2 static_extraction which breaks on first config).
func RunOnHits(hits []YARAHit, data []byte, source string) *ExtractResult {
	for _, hit := range hits {
		family := FamilyFromHit(hit)
		if family == "" {
			continue
		}

		cfg, err := Dispatch(family, data, source)
		if err != nil {
			triggerLog.Warn().
				Err(err).
				Str("family", family).
				Str("rule", hit.RuleName).
				Msg("config extractor error")
			continue
		}
		if cfg == nil {
			triggerLog.Debug().
				Str("family", family).
				Str("rule", hit.RuleName).
				Msg("no config extracted")
			continue
		}

		triggerLog.Info().
			Str("family", family).
			Str("rule", hit.RuleName).
			Str("source", source).
			Strs("c2", cfg.C2Servers).
			Msg("config extracted")

		return &ExtractResult{
			Config:   cfg,
			FamilyID: family,
			HitName:  hit.RuleName,
			Source:   source,
		}
	}
	return nil
}

// RunOnAllHits tries all matched families and returns every successful result.
// Use this when you want complete coverage rather than stopping at first hit.
func RunOnAllHits(hits []YARAHit, data []byte, source string) []*ExtractResult {
	var results []*ExtractResult
	seen := make(map[string]bool)

	for _, hit := range hits {
		family := FamilyFromHit(hit)
		if family == "" || seen[family] {
			continue
		}
		seen[family] = true

		cfg, err := Dispatch(family, data, source)
		if err != nil {
			triggerLog.Warn().Err(err).Str("family", family).Msg("extractor error")
			continue
		}
		if cfg == nil {
			continue
		}

		results = append(results, &ExtractResult{
			Config:   cfg,
			FamilyID: family,
			HitName:  hit.RuleName,
			Source:   source,
		})
	}
	return results
}
