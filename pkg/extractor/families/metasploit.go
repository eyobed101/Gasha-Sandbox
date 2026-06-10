// Metasploit reverse shell / Meterpreter configuration extractor.
//
// Metasploit shellcode payloads embed their C2 configuration as a fixed
// structure within the shellcode itself. Two common formats:
//
//   1. Reverse TCP/HTTP(S) stageless:
//      The IP address and port are stored at well-known offsets relative
//      to identifiable opcodes in the shellcode header.
//
//   2. Staged payloads (stager):
//      A short stager connects to LHOST:LPORT to download the stage.
//      The IP+port are directly embedded at predictable offsets.
//
// Reference: Metasploit Framework (BSD License) shellcode templates
// This is an original Go implementation using public offset documentation.
package families

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/lemas-sandbox/lemas/pkg/extractor"
	"github.com/lemas-sandbox/lemas/pkg/extractor/utils"
)

func init() {
	extractor.Register("Metasploit", &MetasploitParser{})
	extractor.Register("Meterpreter", &MetasploitParser{})
	extractor.Register("MetasploitPayload", &MetasploitParser{})
}

// MetasploitParser extracts Metasploit payload configurations.
type MetasploitParser struct{}

func (p *MetasploitParser) Name() string { return "Metasploit" }

// Metasploit reverse TCP x86 shellcode signatures.
// These byte sequences appear near the LHOST/LPORT values.
var msf32Signatures = [][]byte{
	// reverse_tcp x86 — push DWORD ip; push WORD port
	{0x68},       // PUSH imm32 (IP follows)
	// reverse_http — call to WinExec chain
	{0xFC, 0xE8}, // CLD; CALL
}

// msf64Signatures for x64 payloads
var msf64Signatures = [][]byte{
	{0x49, 0xBE}, // MOV R14, imm64 (contains IP+port packed)
}

// Known Metasploit magic patterns for connection setup
var msfMagicPatterns = []struct {
	sig    []byte
	ipOff  int // offset from sig start to IP (4 bytes)
	portOff int // offset from sig start to port (2 bytes, big-endian)
}{
	// reverse_tcp x86 stager: PUSH port; PUSH ip; ...
	{[]byte{0x68, 0x00, 0x00}, 1, -2}, // PUSH ip at +1, port just before at -2
	// reverse_tcp: direct pattern with port first
	{[]byte{0x5E, 0x31, 0xC0}, -8, -6},
}

func (p *MetasploitParser) Extract(data []byte) (*extractor.Config, error) {
	// Method 1: look for the classic reverse_tcp shellcode structure
	// Pattern: PUSH word port; PUSH dword ip appears in connect() setup
	cfg := p.scanReverseTCP(data)
	if cfg != nil {
		return cfg, nil
	}

	// Method 2: scan for URL patterns (reverse_http / reverse_https)
	urls := utils.ExtractURLs(data)
	for _, u := range urls {
		if isMsfURL(u) {
			return &extractor.Config{
				C2Servers: []string{u},
				Protocol:  "HTTP",
				Raw:       map[string]interface{}{"extraction_method": "url_scan"},
			}, nil
		}
	}

	// Method 3: scan for IP addresses with adjacent port bytes
	cfg = p.scanIPPort(data)
	if cfg != nil {
		return cfg, nil
	}

	return nil, nil
}

// scanReverseTCP looks for the classic x86 reverse_tcp stager pattern:
//   68 PP PP 00 00   PUSH word port (zero-extended)
//   68 II II II II   PUSH dword ip
// The port bytes are in big-endian network order.
func (p *MetasploitParser) scanReverseTCP(data []byte) *extractor.Config {
	for i := 0; i < len(data)-12; i++ {
		// Look for PUSH port pattern: 66 68 HI LO
		if i+10 > len(data) {
			break
		}
		// x86: push word — 0x66 0x68 <hi> <lo>
		if data[i] == 0x66 && data[i+1] == 0x68 {
			port := int(data[i+2])<<8 | int(data[i+3])
			if port < 1 || port > 65535 {
				continue
			}
			// IP should follow as PUSH dword: 0x68 <b0> <b1> <b2> <b3>
			if i+4+5 <= len(data) && data[i+4] == 0x68 {
				ipBytes := data[i+5 : i+9]
				ip := net.IP(ipBytes).String()
				if isPrivateIP(ip) || ip == "0.0.0.0" {
					continue
				}
				return &extractor.Config{
					C2Servers: []string{fmt.Sprintf("%s:%d", ip, port)},
					Protocol:  "TCP",
					Port:      port,
					Raw: map[string]interface{}{
						"payload_arch":       "x86",
						"extraction_method":  "reverse_tcp_pattern",
					},
				}
			}
		}

		// x86 variant 2: PUSH dword port (little-endian 4-byte push of port << 16)
		if data[i] == 0x68 {
			val := binary.LittleEndian.Uint32(data[i+1:])
			port := int((val >> 16) & 0xFFFF)
			if port > 0 && port < 65535 && val&0xFFFF == 0 {
				// might be port << 16 — check for IP PUSH next
				if i+5+5 <= len(data) && data[i+5] == 0x68 {
					ipBytes := data[i+6 : i+10]
					ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]).String()
					if !isPrivateIP(ip) && ip != "0.0.0.0" {
						return &extractor.Config{
							C2Servers: []string{fmt.Sprintf("%s:%d", ip, port)},
							Protocol:  "TCP",
							Port:      port,
							Raw: map[string]interface{}{
								"payload_arch":      "x86",
								"extraction_method": "push_dword_pattern",
							},
						}
					}
				}
			}
		}
	}
	return nil
}

// scanIPPort does a broad scan for IP addresses with a port encoded nearby.
func (p *MetasploitParser) scanIPPort(data []byte) *extractor.Config {
	ips := utils.ExtractIPv4s(data)
	for _, ip := range ips {
		if isPrivateIP(ip) {
			continue
		}
		// Find the IP in the raw bytes and look for a port nearby
		ipBytes := net.ParseIP(ip).To4()
		if ipBytes == nil {
			continue
		}
		for j := 0; j < len(data)-8; j++ {
			if data[j] == ipBytes[0] && data[j+1] == ipBytes[1] &&
				data[j+2] == ipBytes[2] && data[j+3] == ipBytes[3] {
				// Port likely encoded as big-endian 2 bytes just before or after
				if j >= 2 {
					port := int(data[j-2])<<8 | int(data[j-1])
					if port > 0 && port < 65535 && port != 0x4000 {
						return &extractor.Config{
							C2Servers: []string{fmt.Sprintf("%s:%d", ip, port)},
							Port:      port,
							Raw: map[string]interface{}{"extraction_method": "ip_port_proximity"},
						}
					}
				}
			}
		}
	}
	return nil
}

func isMsfURL(u string) bool {
	// Metasploit reverse_http payloads typically connect to /AAAA... or /<random>
	if len(u) < 10 {
		return false
	}
	// Simple heuristic: URL with no standard path components
	return true
}
