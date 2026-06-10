// Generic IOC extractor — fallback for any family with a registered YARA rule
// but no dedicated parser, or for memory dumps where the family is unknown.
//
// Extracts:
//   - All HTTP/HTTPS/FTP URLs
//   - All IPv4 addresses (non-private)
//   - Suspicious domain patterns
//   - Any mutex-like strings
//   - Email addresses (exfil indicators)
//
// This mirrors CAPEv2's behaviour of always attempting IOC extraction even
// when no dedicated family parser is available.
package families

import (
	"regexp"
	"strings"

	"github.com/lemas-sandbox/lemas/pkg/extractor"
	"github.com/lemas-sandbox/lemas/pkg/extractor/utils"
)

func init() {
	extractor.Register("Generic", &GenericParser{})
	extractor.Register("Unknown", &GenericParser{})
}

// GenericParser extracts IOCs from any binary without family-specific logic.
type GenericParser struct{}

func (p *GenericParser) Name() string { return "Generic" }

var (
	domainRE = regexp.MustCompile(
		`(?i)(?:^|[\s"'(])([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+` +
			`(?:com|net|org|io|co|ru|cn|de|fr|uk|xyz|top|pw|tk|ml|ga|cf|gq|onion)(?::\d{2,5})?(?:/[\w./%-]*)?`)
	mutexRE = regexp.MustCompile(`(?i)Global\\[A-Za-z0-9_\-{}\[\]]{6,64}`)
)

func (p *GenericParser) Extract(data []byte) (*extractor.Config, error) {
	cfg := &extractor.Config{
		Raw: make(map[string]interface{}),
	}

	// URLs
	urls := utils.ExtractURLs(data)
	for _, u := range urls {
		if !isPrivateIP(extractHost(u)) {
			cfg.C2Servers = append(cfg.C2Servers, u)
		}
	}

	// IPv4 addresses (non-private)
	for _, ip := range utils.ExtractIPv4s(data) {
		if !isPrivateIP(ip) {
			cfg.C2Servers = append(cfg.C2Servers, ip)
		}
	}

	// Domain patterns
	text := string(data)
	for _, match := range domainRE.FindAllString(text, 50) {
		match = strings.TrimSpace(match)
		match = strings.Trim(match, `"'()`)
		if len(match) > 4 && !strings.HasPrefix(match, "http") {
			cfg.C2Servers = append(cfg.C2Servers, match)
		}
	}

	cfg.C2Servers = utils.Dedup(cfg.C2Servers)

	// Mutex strings
	mutexes := mutexRE.FindAllString(text, 10)
	if len(mutexes) > 0 {
		cfg.Mutex = mutexes[0]
		if len(mutexes) > 1 {
			cfg.Raw["mutexes"] = mutexes
		}
	}

	// ASCII strings (for analyst reference in report)
	strs := utils.ExtractASCIIStrings(data, 8)
	if len(strs) > 0 && len(strs) <= 200 {
		cfg.Raw["strings_sample"] = strs[:min(len(strs), 20)]
	}

	if len(cfg.C2Servers) == 0 && cfg.Mutex == "" {
		return nil, nil
	}
	return cfg, nil
}

func extractHost(url string) string {
	// Strip protocol
	for _, prefix := range []string{"https://", "http://", "ftp://"} {
		if strings.HasPrefix(url, prefix) {
			url = url[len(prefix):]
			break
		}
	}
	// Strip path
	if idx := strings.IndexByte(url, '/'); idx >= 0 {
		url = url[:idx]
	}
	// Strip port
	if idx := strings.LastIndexByte(url, ':'); idx >= 0 {
		url = url[:idx]
	}
	return url
}
