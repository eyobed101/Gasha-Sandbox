package families

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/lemas-sandbox/lemas/pkg/extractor"
	"github.com/lemas-sandbox/lemas/pkg/extractor/utils"
)

func init() {
	extractor.Register("Ursnif", &UrsnifParser{})
	extractor.Register("Dreambot", &UrsnifParser{})
	extractor.Register("Gozi", &UrsnifParser{})
}

type UrsnifParser struct{}

func (p *UrsnifParser) Name() string { return "Ursnif" }

var (
	ursnifSigRC4  = [][]byte{{0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00}, {0x55, 0x8B, 0xEC, 0x83, 0xEC}}
	ursnifCfgKeys = [][]byte{
		[]byte("gozi"), []byte("ursnif"), []byte("dreambot"),
		[]byte("1234567890"), []byte("!@#$%^&*()"),
	}

	ursnifKeyValueRE = regexp.MustCompile(`(?im)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+?)\s*$`)
	ursnifSectionRE  = regexp.MustCompile(`(?im)^\s*\[([^\]]+)\]\s*$`)

	ursnifC2URL = regexp.MustCompile(`(?i)(?:url|c2|server|host|address|gate|gateway)\s*=\s*(https?://[^\s\r\n]+|[\w.-]+:\d{2,5})`)

	ursnifGroupID = regexp.MustCompile(`(?i)(?:group_id|groupid|bot_id|botid|guid)\s*=\s*([a-f0-9]{8,32}|[\w.\-]{4,64})`)
	ursnifPipeRE  = regexp.MustCompile(`(?i)(?:pipe|pipe_name|pipename)\s*=\s*([\w\\\-]{4,64})`)
	ursnifTimerRE = regexp.MustCompile(`(?i)(?:timer|interval|period|timeout)\s*=\s*(\d+)`)
	ursnifMutexRE = regexp.MustCompile(`(?i)(?:mutex|mutex_name)\s*=\s*([\w\-]{4,64})`)
)

func (p *UrsnifParser) Extract(data []byte) (*extractor.Config, error) {
	if cfg := p.scanEncryptedConfig(data); cfg != nil {
		return cfg, nil
	}

	if cfg := p.scanPlainConfig(data); cfg != nil {
		return cfg, nil
	}

	if cfg := p.scanInlineFields(data); cfg != nil {
		return cfg, nil
	}

	return nil, nil
}

func (p *UrsnifParser) scanEncryptedConfig(data []byte) *extractor.Config {
	candidates := p.findEncryptedBlobs(data)
	for _, cand := range candidates {
		for _, key := range ursnifCfgKeys {
			decrypted := utils.RC4Decrypt(key, cand)
			if cfg := p.parseINIConfig(decrypted); cfg != nil {
				cfg.Raw["encryption_key"] = string(key)
				cfg.Raw["extraction_method"] = "rc4_decrypt"
				return cfg
			}
			decrypted = utils.XORDecodeMultiKey(cand, key)
			if cfg := p.parseINIConfig(decrypted); cfg != nil {
				cfg.Raw["encryption_key"] = string(key)
				cfg.Raw["extraction_method"] = "xor_decrypt"
				return cfg
			}
		}
	}
	return nil
}

func (p *UrsnifParser) findEncryptedBlobs(data []byte) [][]byte {
	var blobs [][]byte
	for _, sig := range ursnifSigRC4 {
		for i := 0; i < len(data)-len(sig)-32; i++ {
			match := true
			for j, b := range sig {
				if data[i+j] != b {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			start := i + len(sig)
			end := start + 1024
			if end > len(data) {
				end = len(data)
			}
			blobs = append(blobs, data[start:end])
		}
	}

	rsrcStart := indexBytes(data, []byte{0x52, 0x53, 0x52, 0x43})
	if rsrcStart >= 0 {
		for i := rsrcStart; i < len(data)-32; i++ {
			if data[i] >= 0x80 || data[i] == 0 {
				continue
			}
			sectionLen := 512
			if i+sectionLen > len(data) {
				sectionLen = len(data) - i
			}
			blobs = append(blobs, data[i:i+sectionLen])
			break
		}
	}

	return blobs
}

func (p *UrsnifParser) parseINIConfig(data []byte) *extractor.Config {
	if !hasINIContent(data) {
		return nil
	}

	cfg := &extractor.Config{
		Raw: make(map[string]interface{}),
	}
	_ = cfg

	return p.extractFromText(string(data))
}

func hasINIContent(data []byte) bool {
	if len(data) < 10 {
		return false
	}
	text := string(data)
	printable := 0
	for _, c := range text {
		if c >= 0x20 && c <= 0x7E || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	if printable < len(data)/2 {
		return false
	}
	return strings.Contains(text, "=") && strings.Contains(text, "[")
}

func (p *UrsnifParser) scanPlainConfig(data []byte) *extractor.Config {
	text := string(data)
	if !strings.Contains(text, "=") {
		return nil
	}
	return p.extractFromText(text)
}

func (p *UrsnifParser) extractFromText(text string) *extractor.Config {
	cfg := &extractor.Config{
		Raw: make(map[string]interface{}),
	}

	sections := ursnifSectionRE.FindAllString(text, -1)
	cfg.Raw["config_sections"] = sections

	pairs := ursnifKeyValueRE.FindAllStringSubmatch(text, 50)
	if len(pairs) == 0 {
		if urls := utils.ExtractURLs([]byte(text)); len(urls) > 0 {
			cfg.C2Servers = urls
			cfg.Protocol = "HTTP"
			cfg.Raw["extraction_method"] = "url_extract"
			return cfg
		}
		return nil
	}

	seen := make(map[string]string)
	for _, pair := range pairs {
		key := strings.ToLower(strings.TrimSpace(pair[1]))
		val := strings.TrimSpace(pair[2])
		seen[key] = val
	}

	for k, v := range seen {
		switch {
		case strings.Contains(k, "url") || strings.Contains(k, "c2") || strings.Contains(k, "server") || strings.Contains(k, "host") || strings.Contains(k, "address") || strings.Contains(k, "gate"):
			cfg.C2Servers = append(cfg.C2Servers, v)
			if strings.HasPrefix(strings.ToLower(v), "http") {
				cfg.Protocol = "HTTP"
			}
		case strings.Contains(k, "group") || strings.Contains(k, "bot_id") || strings.Contains(k, "guid"):
			cfg.Raw["group_id"] = v
		case strings.Contains(k, "pipe"):
			cfg.Raw["pipe_name"] = v
		case strings.Contains(k, "timer") || strings.Contains(k, "interval") || strings.Contains(k, "period") || strings.Contains(k, "timeout"):
			cfg.Raw["timer"] = v
		case strings.Contains(k, "mutex"):
			cfg.Mutex = v
		case strings.Contains(k, "user") || strings.Contains(k, "agent") || strings.Contains(k, "ua"):
			cfg.Raw["user_agent"] = v
		case strings.Contains(k, "key") || strings.Contains(k, "password"):
			cfg.Raw[k] = v
		case strings.Contains(k, "port"):
			fmt.Sscanf(v, "%d", &cfg.Port)
		}
	}

	cfg.C2Servers = utils.Dedup(cfg.C2Servers)

	if len(cfg.C2Servers) == 0 && len(cfg.Raw) <= 1 {
		return nil
	}
	cfg.Raw["extraction_method"] = "ini_config"
	return cfg
}

func (p *UrsnifParser) scanInlineFields(data []byte) *extractor.Config {
	text := string(data)
	cfg := &extractor.Config{
		Raw: make(map[string]interface{}),
	}

	urls := ursnifC2URL.FindAllStringSubmatch(text, 10)
	for _, m := range urls {
		cfg.C2Servers = append(cfg.C2Servers, m[1])
	}

	group := ursnifGroupID.FindStringSubmatch(text)
	if len(group) > 1 {
		cfg.Raw["group_id"] = group[1]
	}

	pipe := ursnifPipeRE.FindStringSubmatch(text)
	if len(pipe) > 1 {
		cfg.Raw["pipe_name"] = pipe[1]
	}

	timer := ursnifTimerRE.FindStringSubmatch(text)
	if len(timer) > 1 {
		cfg.Raw["timer"] = timer[1]
	}

	mutex := ursnifMutexRE.FindStringSubmatch(text)
	if len(mutex) > 1 {
		cfg.Mutex = mutex[1]
	}

	cfg.C2Servers = utils.Dedup(cfg.C2Servers)

	if len(cfg.C2Servers) > 0 {
		cfg.Protocol = "HTTP"
		cfg.Raw["extraction_method"] = "inline_regex"
	}

	if len(cfg.C2Servers) == 0 && len(cfg.Raw) == 0 {
		return nil
	}
	return cfg
}

func indexBytes(data, needle []byte) int {
	if len(needle) == 0 || len(data) < len(needle) {
		return -1
	}
	for i := 0; i <= len(data)-len(needle); i++ {
		match := true
		for j := range needle {
			if data[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
