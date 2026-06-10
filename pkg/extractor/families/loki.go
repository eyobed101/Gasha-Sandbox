package families

import (
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/lemas-sandbox/lemas/pkg/extractor"
	"github.com/lemas-sandbox/lemas/pkg/extractor/utils"
)

func init() {
	extractor.Register("Loki", &LokiParser{})
	extractor.Register("LokiBot", &LokiParser{})
	extractor.Register("Loki Bot", &LokiParser{})
}

type LokiParser struct{}

func (p *LokiParser) Name() string { return "Loki" }

var (
	lokiC2RE       = regexp.MustCompile(`(?i)(?:C2|Server|Host|URL|Address|Panel)\s*[:=]\s*["']?(https?://[^\s"',;]+|[\w.-]+:\d{2,5})`)
	lokiFTPRE      = regexp.MustCompile(`(?i)(?:ftp://|ftps://)[\w:@./-]+`)
	lokiInstallRE  = regexp.MustCompile(`(?i)(?:Install|InstallName|RegistryKey)\s*[:=]\s*["']?([A-Za-z0-9_\-\\{}]{3,64})`)
	lokiPeriodRE   = regexp.MustCompile(`(?i)(?:Period|Interval|Sleep|Timer)\s*[:=]\s*["']?(\d+)`)
	lokiKeyRE      = regexp.MustCompile(`(?i)(?:Key|EncryptionKey|Password)\s*[:=]\s*["']?([A-Za-z0-9_\-]{4,64})`)
	lokiMutexRE    = regexp.MustCompile(`(?i)(?:Mutex|MutexName)\s*[:=]\s*["']?([A-Za-z0-9_\-]{4,64})`)
	lokiEmailSMTP  = regexp.MustCompile(`(?i)(?:SMTP|Mail|Email)\s*[:=]\s*["']?([\w.%+\-]+@[\w.\-]+\.[\w]{2,})`)
	lokiExfilRE    = regexp.MustCompile(`(?i)(?:exfil|exfiltration|stealer_method|type)\s*[:=]\s*["']?(smtp|ftp|http|telegram|email)`)
)

func (p *LokiParser) Extract(data []byte) (*extractor.Config, error) {
	decoded := p.tryDecodeStrings(data)
	text := string(decoded)
	_ = text

	if cfg := p.extractConfig(decoded); cfg != nil {
		return cfg, nil
	}

	return nil, nil
}

func (p *LokiParser) tryDecodeStrings(data []byte) []byte {
	text := string(data)
	var results []byte
	results = append(results, data...)

	b64RE := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	for _, match := range b64RE.FindAllString(text, 10) {
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(match)
			if err != nil {
				continue
			}
		}
		printable := 0
		for _, b := range decoded {
			if b >= 0x20 && b <= 0x7E {
				printable++
			}
		}
		if printable > len(decoded)/2 {
			results = append(results, '\n')
			results = append(results, decoded...)
		}
	}

	xorKeys := []byte{0x95, 0xBC, 0xAA, 0x55, 0x11, 0x22, 0x33, 0x44, 0x77}
	for _, k := range xorKeys {
		decoded := utils.XORDecode(data, k)
		printable := 0
		for _, b := range decoded {
			if b >= 0x20 && b <= 0x7E {
				printable++
			}
		}
		if printable > len(decoded)*3/4 {
			results = append(results, '\n')
			results = append(results, decoded...)
		}
	}

	return results
}

func (p *LokiParser) extractConfig(data []byte) *extractor.Config {
	text := string(data)
	cfg := &extractor.Config{
		Raw: make(map[string]interface{}),
	}

	cfg.Raw["extraction_method"] = "field_scan"

	c2s := lokiC2RE.FindAllStringSubmatch(text, 10)
	for _, m := range c2s {
		val := strings.Trim(m[1], `"' `)
		cfg.C2Servers = append(cfg.C2Servers, val)
		if strings.HasPrefix(strings.ToLower(val), "http") {
			cfg.Protocol = "HTTP"
		}
	}

	ftps := lokiFTPRE.FindAllString(text, 5)
	for _, f := range ftps {
		cfg.C2Servers = append(cfg.C2Servers, f)
		if cfg.Protocol == "" {
			cfg.Protocol = "FTP"
		}
	}

	emails := lokiEmailSMTP.FindAllStringSubmatch(text, 3)
	if len(emails) > 0 {
		cfg.Raw["smtp_email"] = emails[0][1]
		cfg.Protocol = "SMTP"
	}

	install := lokiInstallRE.FindStringSubmatch(text)
	if len(install) > 1 {
		cfg.Raw["install_name"] = install[1]
	}

	period := lokiPeriodRE.FindStringSubmatch(text)
	if len(period) > 1 {
		cfg.Raw["period"] = period[1]
	}

	key := lokiKeyRE.FindStringSubmatch(text)
	if len(key) > 1 {
		cfg.Raw["encryption_key"] = key[1]
	}

	mutex := lokiMutexRE.FindStringSubmatch(text)
	if len(mutex) > 1 {
		cfg.Mutex = mutex[1]
	}

	exfil := lokiExfilRE.FindStringSubmatch(text)
	if len(exfil) > 1 {
		cfg.Raw["exfil_method"] = strings.ToLower(exfil[1])
	}

	cfg.C2Servers = utils.Dedup(cfg.C2Servers)

	if len(cfg.C2Servers) == 0 && len(cfg.Raw) <= 1 {
		return nil
	}
	return cfg
}
