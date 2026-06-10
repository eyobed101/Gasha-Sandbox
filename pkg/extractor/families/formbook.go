package families

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"

	"github.com/lemas-sandbox/lemas/pkg/extractor"
	"github.com/lemas-sandbox/lemas/pkg/extractor/utils"
)

func init() {
	extractor.Register("FormBook", &FormBookParser{})
	extractor.Register("Formbook", &FormBookParser{})
}

type FormBookParser struct{}

func (p *FormBookParser) Name() string { return "FormBook" }

var formBookCfgRE = regexp.MustCompile(`(?s)(<FormBook[^>]*>.*?</FormBook>|<formbook[^>]*>.*?</formbook>)`)

var formBookFieldRE = regexp.MustCompile(`(?i)(?:Server|URL|C2|Address|CampaignID|GroupID|Password|Mutex)\s*[:=]\s*([^\s\x00"',;]{3,})`)

var formBookKeyOffsets = []struct {
	sig   []byte
	xorKey byte
	skip   int
}{
	{[]byte{0x8B, 0x0D}, 0x95, 2},
	{[]byte{0xB9}, 0xBC, 1},
}

func (p *FormBookParser) Extract(data []byte) (*extractor.Config, error) {
	text := string(data)

	if cfg := p.scanXMLConfig(text); cfg != nil {
		return cfg, nil
	}

	if cfg := p.scanFieldPairs(text); cfg != nil {
		return cfg, nil
	}

	if cfg := p.scanXORConfig(data); cfg != nil {
		return cfg, nil
	}

	if cfg := p.scanFallbackIOC(data); cfg != nil {
		return cfg, nil
	}

	return nil, nil
}

func (p *FormBookParser) scanXMLConfig(text string) *extractor.Config {
	match := formBookCfgRE.FindString(text)
	if match == "" {
		return nil
	}

	type xmlFormBook struct {
		Server     string `xml:"Server,attr"`
		URL        string `xml:"URL,attr"`
		CampaignID string `xml:"CampaignID,attr"`
		Password   string `xml:"Password,attr"`
		Mutex      string `xml:"Mutex,attr"`
	}

	var cfg xmlFormBook
	if err := xml.Unmarshal([]byte(match), &cfg); err != nil {
		return nil
	}

	result := &extractor.Config{
		Raw: map[string]interface{}{"extraction_method": "xml"},
	}

	if cfg.Server != "" {
		result.C2Servers = append(result.C2Servers, cfg.Server)
	}
	if cfg.URL != "" {
		result.C2Servers = append(result.C2Servers, cfg.URL)
	}
	if cfg.Password != "" {
		result.Raw["password"] = cfg.Password
	}
	if cfg.CampaignID != "" {
		result.Raw["campaign_id"] = cfg.CampaignID
	}
	if cfg.Mutex != "" {
		result.Mutex = cfg.Mutex
	}
	if strings.HasPrefix(strings.ToLower(cfg.Server), "http") || strings.HasPrefix(strings.ToLower(cfg.URL), "http") {
		result.Protocol = "HTTP"
	}

	if len(result.C2Servers) == 0 && len(result.Raw) == 0 {
		return nil
	}
	return result
}

func (p *FormBookParser) scanFieldPairs(text string) *extractor.Config {
	matches := formBookFieldRE.FindAllStringSubmatch(text, 20)
	if len(matches) < 2 {
		return nil
	}

	result := &extractor.Config{
		Raw: map[string]interface{}{"extraction_method": "field_pairs"},
	}

	for _, m := range matches {
		val := strings.TrimSpace(m[1])
		line := strings.ToLower(m[0])
		switch {
		case strings.Contains(line, "server") || strings.Contains(line, "url") || strings.Contains(line, "c2") || strings.Contains(line, "address"):
			result.C2Servers = append(result.C2Servers, val)
			if strings.HasPrefix(strings.ToLower(val), "http") {
				result.Protocol = "HTTP"
			}
		case strings.Contains(line, "campaign") || strings.Contains(line, "group"):
			result.Raw["campaign_id"] = val
		case strings.Contains(line, "password"):
			result.Raw["password"] = val
		case strings.Contains(line, "mutex"):
			result.Mutex = val
		}
	}

	result.C2Servers = utils.Dedup(result.C2Servers)
	if len(result.C2Servers) == 0 && len(result.Raw) == 0 {
		return nil
	}
	return result
}

func (p *FormBookParser) scanXORConfig(data []byte) *extractor.Config {
	for _, pattern := range formBookKeyOffsets {
		for i := 0; i < len(data)-20; i++ {
			if i+len(pattern.sig) > len(data) {
				break
			}
			match := true
			for j, b := range pattern.sig {
				if data[i+j] != b {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			start := i + pattern.skip
			end := start + 128
			if end > len(data) {
				end = len(data)
			}
			decoded := utils.XORDecode(data[start:end], pattern.xorKey)
			text := string(decoded)
			urls := utils.ExtractURLs([]byte(text))
			if len(urls) > 0 {
				return &extractor.Config{
					C2Servers: urls,
					Protocol:  "HTTP",
					Raw: map[string]interface{}{
						"extraction_method": "xor_decode",
						"xor_key":           fmt.Sprintf("0x%02X", pattern.xorKey),
					},
				}
			}
		}
	}
	return nil
}

func (p *FormBookParser) scanFallbackIOC(data []byte) *extractor.Config {
	var c2s []string

	urls := utils.ExtractURLs(data)
	for _, u := range urls {
		host := extractHost(u)
		if !isPrivateIP(host) {
			c2s = append(c2s, u)
		}
	}

	ips := utils.ExtractIPv4s(data)
	for _, ip := range ips {
		if !isPrivateIP(ip) {
			c2s = append(c2s, ip)
		}
	}

	c2s = utils.Dedup(c2s)
	if len(c2s) == 0 {
		return nil
	}
	return &extractor.Config{
		C2Servers: c2s,
		Raw:       map[string]interface{}{"extraction_method": "fallback_ioc"},
	}
}
