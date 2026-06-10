// Package utils provides low-level binary analysis helpers used by family
// parsers. These are Go equivalents of CAPEv2's extractor_utils.py functions,
// adapted for pure-Go PE parsing via saferwall/pe.
package utils

import (
	"encoding/binary"
	"fmt"
)

// ─── .NET helpers ─────────────────────────────────────────────────────────────

// MDToken extracts a .NET metadata token from the first 4 bytes of data.
// Equivalent to: struct.unpack_from("<I", data)[0] & 0xFFFFFF
func MDToken(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(data) & 0xFFFFFF
}

// ─── PE section helpers ───────────────────────────────────────────────────────

// Section describes a minimal PE section for alignment calculations.
// Populated from saferwall/pe or our own PE header parser.
type Section struct {
	Name             string
	VirtualAddress   uint32
	PointerToRawData uint32
	VirtualSize      uint32
	RawSize          uint32
}

// CalcSectionAlignment returns the alignment delta between the section
// containing offset and the section containing (offset + addr).
//
// Go equivalent of extractor_utils.calc_section_alignment():
//   alignment = (rdataVA - textVA) - (rdataRaw - textRaw)
//
// Returns 0 if either section is not found.
func CalcSectionAlignment(sections []Section, offset, addr uint32) uint32 {
	text := sectionContaining(sections, offset)
	rdata := sectionContaining(sections, offset+addr)
	if text == nil || rdata == nil {
		return 0
	}
	va := int64(rdata.VirtualAddress) - int64(text.VirtualAddress)
	raw := int64(rdata.PointerToRawData) - int64(text.PointerToRawData)
	delta := va - raw
	if delta < 0 {
		return 0
	}
	return uint32(delta)
}

// DataOffset converts a string_offset + relative addr into a raw file offset.
// Equivalent to extractor_utils.get_data_offset().
func DataOffset(sections []Section, stringOffset, addr uint32) uint32 {
	alignment := CalcSectionAlignment(sections, stringOffset, addr)
	return stringOffset + addr - alignment
}

func sectionContaining(sections []Section, rva uint32) *Section {
	for i := range sections {
		s := &sections[i]
		end := s.VirtualAddress + s.VirtualSize
		if end == 0 {
			end = s.VirtualAddress + s.RawSize
		}
		if rva >= s.VirtualAddress && rva < end {
			return s
		}
	}
	return nil
}

// ─── CALL xref scanner ────────────────────────────────────────────────────────

// CallXref represents a CALL instruction found during scanning.
type CallXref struct {
	// From is the file offset of the E8 CALL opcode.
	From uint32
	// Target is the file offset of the called function.
	Target uint32
}

// FindCallXrefs scans data[start:end] for E8 CALL instructions and returns
// a map of target_offset → []source_offsets.
//
// Go equivalent of extractor_utils.find_function_xrefs().
// Filters out false positives using the same heuristic as the Python original:
// skips CALLs preceded by data-manipulation opcodes (0x81 0x40, 0xC7 0x45 etc.)
func FindCallXrefs(data []byte, start, end uint32) map[uint32][]uint32 {
	if end > uint32(len(data)) {
		end = uint32(len(data))
	}
	result := make(map[uint32][]uint32)

	// False-positive prefixes — same list as Python original
	falsePositivePrefixes := [][2]byte{
		{0x81, 0x40}, {0x81, 0x45}, {0x81, 0x75},
		{0xC7, 0x40}, {0xC7, 0x45}, {0xC7, 0x75},
	}

	for rva := start; rva < end; rva++ {
		if int(rva)+5 > len(data) {
			break
		}
		if data[rva] != 0xE8 {
			continue
		}
		// Check for false-positive prefix
		if rva >= 2 {
			prefix := [2]byte{data[rva-2], data[rva-1]}
			isFP := false
			for _, fp := range falsePositivePrefixes {
				if prefix == fp {
					isFP = true
					break
				}
			}
			if isFP {
				continue
			}
		}
		// Decode 32-bit signed relative offset
		rel := int32(binary.LittleEndian.Uint32(data[rva+1:]))
		// Target = next instruction (rva+5) + rel
		rawTarget := int64(rva) + 5 + int64(rel)
		if rawTarget < int64(start) || rawTarget >= int64(end) {
			continue
		}
		target := uint32(rawTarget)
		result[target] = append(result[target], rva)
	}
	return result
}

// ─── XOR helpers ──────────────────────────────────────────────────────────────

// XORDecode returns a new byte slice with every byte XOR'd by key.
func XORDecode(data []byte, key byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key
	}
	return out
}

// XORDecodeMultiKey decodes data with a multi-byte repeating XOR key.
func XORDecodeMultiKey(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// ─── RC4 ──────────────────────────────────────────────────────────────────────

// RC4Decrypt performs RC4 key-scheduling and decryption in place.
// Returns the decrypted bytes.
func RC4Decrypt(key, data []byte) []byte {
	// Key schedule
	s := make([]byte, 256)
	for i := range s {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) & 0xFF
		s[i], s[j] = s[j], s[i]
	}
	// Decrypt
	out := make([]byte, len(data))
	i, k := 0, 0
	for n, b := range data {
		i = (i + 1) & 0xFF
		k = (k + int(s[i])) & 0xFF
		s[i], s[k] = s[k], s[i]
		out[n] = b ^ s[(int(s[i])+int(s[k]))&0xFF]
	}
	return out
}

// ─── String extraction ────────────────────────────────────────────────────────

// ExtractASCIIStrings returns all printable ASCII strings of length >= minLen
// found in data. Equivalent to the common "strings" utility.
func ExtractASCIIStrings(data []byte, minLen int) []string {
	var results []string
	start := -1
	for i, b := range data {
		if b >= 0x20 && b <= 0x7E {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 && i-start >= minLen {
				results = append(results, string(data[start:i]))
			}
			start = -1
		}
	}
	if start >= 0 && len(data)-start >= minLen {
		results = append(results, string(data[start:]))
	}
	return results
}

// ExtractURLs returns all HTTP/HTTPS/FTP URLs found in data.
func ExtractURLs(data []byte) []string {
	text := string(data)
	var urls []string
	prefixes := []string{"http://", "https://", "ftp://"}
	for _, prefix := range prefixes {
		pos := 0
		for {
			idx := indexString(text[pos:], prefix)
			if idx < 0 {
				break
			}
			start := pos + idx
			end := start + len(prefix)
			for end < len(text) {
				c := text[end]
				if c == ' ' || c == '\r' || c == '\n' || c == '\t' || c == '"' || c == '\'' || c == '\x00' {
					break
				}
				end++
			}
			if end-start > len(prefix)+3 {
				urls = append(urls, text[start:end])
			}
			pos = start + 1
		}
	}
	return urls
}

// ─── IP/domain helpers ────────────────────────────────────────────────────────

// ExtractIPv4s returns all IPv4 addresses found as strings in data.
func ExtractIPv4s(data []byte) []string {
	text := string(data)
	var ips []string
	// Simple dotted-decimal scan
	for i := 0; i < len(text)-7; i++ {
		if !isDigit(text[i]) {
			continue
		}
		end := i
		dots := 0
		for end < len(text) && (isDigit(text[end]) || text[end] == '.') {
			if text[end] == '.' {
				dots++
			}
			end++
		}
		if dots == 3 {
			candidate := text[i:end]
			if isValidIPv4String(candidate) {
				ips = append(ips, candidate)
				i = end - 1
			}
		}
	}
	return Dedup(ips)
}

// ─── Utility helpers ──────────────────────────────────────────────────────────

func indexString(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isValidIPv4String(s string) bool {
	parts := splitDot(s)
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		val := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			val = val*10 + int(c-'0')
		}
		if val > 255 {
			return false
		}
	}
	return true
}

func splitDot(s string) []string {
	var parts []string
	start := 0
	for i, c := range s {
		if c == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func Dedup(ss []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// NullTerminated returns the bytes up to the first 0x00 byte.
func NullTerminated(data []byte) []byte {
	for i, b := range data {
		if b == 0 {
			return data[:i]
		}
	}
	return data
}

// PrintableASCII returns true if all bytes in s are printable ASCII (0x20–0x7E).
func PrintableASCII(s string) bool {
	for _, c := range s {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// FormatHex returns a hex string from bytes with optional separator.
func FormatHex(data []byte, sep string) string {
	if len(data) == 0 {
		return ""
	}
	result := fmt.Sprintf("%02X", data[0])
	for _, b := range data[1:] {
		result += sep + fmt.Sprintf("%02X", b)
	}
	return result
}
