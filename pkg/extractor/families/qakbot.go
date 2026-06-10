// QakBot (QBot) configuration extractor.
//
// QakBot stores its C2 configuration as an RC4-encrypted binary blob.
// The encryption key is derived from the campaign ID embedded in the PE.
//
// Config structure (after decryption):
//   count:uint32  followed by count * { ip:uint32, port:uint16 } entries
//
// Reference: public malware analysis reports (ANY.RUN, Trellix, Sekoia)
// This is an original Go implementation based on the public format spec.
package families

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/lemas-sandbox/lemas/pkg/extractor"
	"github.com/lemas-sandbox/lemas/pkg/extractor/utils"
)

func init() {
	extractor.Register("QakBot", &QakBotParser{})
	extractor.Register("Qbot", &QakBotParser{})
}

// QakBotParser extracts QakBot C2 configurations.
type QakBotParser struct{}

func (p *QakBotParser) Name() string { return "QakBot" }

// Known QakBot RC4 key patterns. The key is typically a 20-byte value
// derived from the campaign string embedded in the .data section.
// We also try common hardcoded keys from known campaigns.
var qakbotKnownKeys = [][]byte{
	// Campaign IDs as ASCII → used as RC4 key directly
	[]byte("obama"),
	[]byte("BB"),
	[]byte("abc"),
}

// qakbotMagic is the expected first byte of a decrypted QakBot C2 list.
// A valid decrypted block starts with a count that makes sense (1–256 entries).
const qakbotMaxC2Count = 256

func (p *QakBotParser) Extract(data []byte) (*extractor.Config, error) {
	// Strategy 1: scan for the RC4-encrypted C2 block signature
	// QakBot encodes its C2 list as: [rc4_key_len:1][rc4_key:N][encrypted_data]
	// Key length is typically 20 bytes for SHA1-derived keys.
	for _, candidate := range findQakBotBlobs(data) {
		if cfg := p.tryDecodeBlob(candidate); cfg != nil {
			return cfg, nil
		}
	}

	// Strategy 2: scan for plaintext IP:port pairs in .data sections
	// (some QakBot variants store fallback C2 unencrypted)
	ips := utils.ExtractIPv4s(data)
	if len(ips) > 0 {
		var c2s []string
		for _, ip := range ips {
			// Skip private/loopback addresses
			if isPrivateIP(ip) {
				continue
			}
			c2s = append(c2s, ip)
		}
		if len(c2s) >= 3 { // QakBot typically has 3+ C2s
			return &extractor.Config{
				C2Servers: c2s,
				Raw:       map[string]interface{}{"extraction_method": "plaintext_scan"},
			}, nil
		}
	}

	return nil, nil
}

// findQakBotBlobs heuristically locates candidate encrypted C2 blobs.
// Looks for regions that are preceded by a plausible RC4 key length byte.
func findQakBotBlobs(data []byte) [][]byte {
	var candidates [][]byte
	for i := 0; i < len(data)-10; i++ {
		keyLen := int(data[i])
		if keyLen < 4 || keyLen > 40 {
			continue
		}
		if i+1+keyLen+6 > len(data) {
			continue
		}
		key := data[i+1 : i+1+keyLen]
		encrypted := data[i+1+keyLen:]
		// Minimum viable blob is 4 (count) + 6 (one entry) = 10 bytes
		if len(encrypted) < 10 {
			continue
		}
		decrypted := utils.RC4Decrypt(key, encrypted[:min(len(encrypted), 1024)])
		candidates = append(candidates, decrypted)
	}
	return candidates
}

func (p *QakBotParser) tryDecodeBlob(data []byte) *extractor.Config {
	if len(data) < 6 {
		return nil
	}
	count := binary.LittleEndian.Uint32(data[0:4])
	if count == 0 || count > qakbotMaxC2Count {
		return nil
	}
	if uint32(len(data)) < 4+count*6 {
		return nil
	}

	var c2s []string
	for i := uint32(0); i < count; i++ {
		off := 4 + i*6
		ipBytes := data[off : off+4]
		port := binary.BigEndian.Uint16(data[off+4 : off+6])

		ip := net.IP(ipBytes).String()
		if isPrivateIP(ip) || ip == "0.0.0.0" {
			continue
		}
		c2s = append(c2s, fmt.Sprintf("%s:%d", ip, port))
	}

	if len(c2s) == 0 {
		return nil
	}
	return &extractor.Config{
		C2Servers: c2s,
		Raw: map[string]interface{}{
			"entry_count": count,
		},
	}
}

func isPrivateIP(ip string) bool {
	private := []string{"10.", "172.1", "172.2", "172.3", "192.168.", "127.", "0."}
	for _, p := range private {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
