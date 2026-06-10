// Agent Tesla configuration extractor.
//
// Agent Tesla is a .NET-based infostealer/RAT. It stores its configuration
// as obfuscated strings within the .NET assembly's string heap or as
// XOR-encoded literals in the code section.
//
// Config fields typically include:
//   - SMTP host, port, username, password (for email exfiltration)
//   - FTP host, username, password
//   - Telegram bot token + chat ID
//   - C2 URL (HTTP panel)
//
// Extraction approach:
//   1. Scan for recognisable credential patterns (email addresses, SMTP ports)
//   2. Scan .NET string heap for URL/credential literals
//   3. Look for base64-encoded strings (common obfuscation)
//
// Reference: public malware analysis (ANY.RUN, Proofpoint, Recorded Future)
// Original Go implementation.
package families

import (
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/lemas-sandbox/lemas/pkg/extractor"
	"github.com/lemas-sandbox/lemas/pkg/extractor/utils"
)

func init() {
	extractor.Register("AgentTesla", &AgentTeslaParser{})
	extractor.Register("Agent Tesla", &AgentTeslaParser{})
}

// AgentTeslaParser extracts Agent Tesla configurations.
type AgentTeslaParser struct{}

func (p *AgentTeslaParser) Name() string { return "AgentTesla" }

var (
	// SMTP server patterns
	smtpPortRE = regexp.MustCompile(`(?i)(smtp\.[\w.-]+\.\w{2,}|mail\.[\w.-]+\.\w{2,})`)
	// Telegram bot token pattern: digits:alphanum
	telegramTokenRE = regexp.MustCompile(`\d{8,10}:[A-Za-z0-9_-]{35}`)
	// Telegram chat ID
	telegramChatRE = regexp.MustCompile(`-?\d{7,13}`)
	// FTP URL
	ftpRE = regexp.MustCompile(`ftp://[\w:@.-]+`)
	// Email for SMTP exfil
	emailRE = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	// HTTP panel URL
	httpPanelRE = regexp.MustCompile(`https?://[\w./-]+/[\w./%-]+\.php`)
)

func (p *AgentTeslaParser) Extract(data []byte) (*extractor.Config, error) {
	cfg := &extractor.Config{
		Raw: make(map[string]interface{}),
	}

	// Decode any base64 blobs first — Agent Tesla commonly base64-encodes
	// its config strings to defeat simple string scans
	expanded := p.expandBase64(data)
	workData := append(data, expanded...)

	text := string(workData)

	// C2 via HTTP panel
	panelURLs := httpPanelRE.FindAllString(text, -1)
	if len(panelURLs) > 0 {
		cfg.C2Servers = append(cfg.C2Servers, utils.Dedup(panelURLs)...)
		cfg.Protocol = "HTTP"
	}

	// FTP exfiltration
	ftpURLs := ftpRE.FindAllString(text, -1)
	if len(ftpURLs) > 0 {
		cfg.C2Servers = append(cfg.C2Servers, ftpURLs...)
		cfg.Protocol = "FTP"
		cfg.Raw["exfil_method"] = "ftp"
	}

	// SMTP exfiltration
	smtpHosts := smtpPortRE.FindAllString(text, 3)
	if len(smtpHosts) > 0 {
		cfg.Raw["smtp_host"] = smtpHosts[0]
		cfg.Protocol = "SMTP"
		// Find associated email credential
		emails := emailRE.FindAllString(text, 5)
		if len(emails) > 0 {
			cfg.Raw["smtp_email"] = emails[0]
		}
	}

	// Telegram C2
	telegramTokens := telegramTokenRE.FindAllString(text, 3)
	if len(telegramTokens) > 0 {
		cfg.Raw["telegram_token"] = telegramTokens[0]
		cfg.Protocol = "Telegram"
		cfg.C2Servers = append(cfg.C2Servers, "api.telegram.org")
	}

	// Extract any plaintext URLs
	urls := utils.ExtractURLs(workData)
	for _, u := range urls {
		if strings.Contains(u, "telegram.org") || strings.Contains(u, ".php") {
			cfg.C2Servers = append(cfg.C2Servers, u)
		}
	}
	cfg.C2Servers = utils.Dedup(cfg.C2Servers)

	// Only return a result if we found something meaningful
	if len(cfg.C2Servers) == 0 && len(cfg.Raw) == 0 {
		return nil, nil
	}
	return cfg, nil
}

// expandBase64 finds base64-encoded blobs in data and returns the decoded
// concatenation. Minimum viable base64 string is 20 chars.
func (p *AgentTeslaParser) expandBase64(data []byte) []byte {
	b64RE := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	var out []byte
	for _, match := range b64RE.FindAll(data, -1) {
		decoded, err := base64.StdEncoding.DecodeString(string(match))
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(string(match))
			if err != nil {
				continue
			}
		}
		// Only append if decoded content looks like printable text
		printable := 0
		for _, b := range decoded {
			if b >= 0x20 && b <= 0x7E {
				printable++
			}
		}
		if printable > len(decoded)/2 {
			out = append(out, decoded...)
			out = append(out, '\n')
		}
	}
	return out
}
