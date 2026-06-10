// Package procdump provides a reader for the LEMAS memory dump format.
//
// Memory dumps are written as a sequence of region headers followed by raw
// page data. The format is binary-compatible with CAPEv2's ProcDump format:
//
//   [addr:uint64][size:uint32][mem_state:uint32][mem_type:uint32][mem_prot:uint32]
//   followed by `size` bytes of raw content
//
// This is a Go equivalent of objects.ProcDump in CAPEv2.
package procdump

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"regexp"
)

// Protection flags — matches Windows MEMORY_BASIC_INFORMATION values.
const (
	PageNoAccess          = 0x01
	PageReadOnly          = 0x02
	PageReadWrite         = 0x04
	PageWriteCopy         = 0x08
	PageExecute           = 0x10
	PageExecuteRead       = 0x20
	PageExecuteReadWrite  = 0x40
	PageExecuteWriteCopy  = 0x80
	PageGuard             = 0x100
)

// Chunk is a single committed memory region.
type Chunk struct {
	Start  uint64
	End    uint64
	Size   uint32
	Prot   uint32
	State  uint32
	Type   uint32
	Offset int64  // byte offset into the dump file where data begins
	IsPE   bool   // true if region starts with MZ header
}

// Region is a group of contiguous chunks coalesced into one logical block.
type Region struct {
	Start  uint64
	End    uint64
	Size   uint64
	Prot   uint32  // nil-equivalent = 0 when chunks have mixed perms
	IsPE   bool
	Chunks []Chunk
}

// Dump is a parsed process memory dump.
type Dump struct {
	file    *os.File
	Regions []Region
}

// chunkHeaderSize is the fixed binary header size per chunk (matches struct "QIIII").
const chunkHeaderSize = 24 // 8 + 4 + 4 + 4 + 4

// Open parses a memory dump file and returns a Dump ready for data access.
func Open(path string) (*Dump, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("procdump: open %s: %w", path, err)
	}
	d := &Dump{file: f}
	if err := d.parse(); err != nil {
		f.Close()
		return nil, err
	}
	return d, nil
}

// Close releases the underlying file handle.
func (d *Dump) Close() error {
	if d.file != nil {
		return d.file.Close()
	}
	return nil
}

func (d *Dump) parse() error {
	var (
		curChunks []Chunk
		lastEnd   uint64
	)

	for {
		hdr := make([]byte, chunkHeaderSize)
		_, err := io.ReadFull(d.file, hdr)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return fmt.Errorf("procdump: read header: %w", err)
		}

		addr := binary.LittleEndian.Uint64(hdr[0:])
		size := binary.LittleEndian.Uint32(hdr[8:])
		memState := binary.LittleEndian.Uint32(hdr[12:])
		memType  := binary.LittleEndian.Uint32(hdr[16:])
		memProt  := binary.LittleEndian.Uint32(hdr[20:])

		// Coalesce break: if address is not contiguous, finalise current group
		if addr != lastEnd && len(curChunks) > 0 {
			d.Regions = append(d.Regions, coalesce(curChunks))
			curChunks = nil
		}
		lastEnd = addr + uint64(size)

		// Record data offset (current position = just after header)
		dataOffset, _ := d.file.Seek(0, io.SeekCurrent)

		// Peek at first 2 bytes to detect MZ header
		isMZ := false
		peek := make([]byte, 2)
		n, _ := d.file.Read(peek)
		if n == 2 && peek[0] == 'M' && peek[1] == 'Z' {
			isMZ = true
		}

		// Seek past the data region
		if _, err := d.file.Seek(dataOffset+int64(size), io.SeekStart); err != nil {
			break
		}

		curChunks = append(curChunks, Chunk{
			Start:  addr,
			End:    addr + uint64(size),
			Size:   size,
			Prot:   memProt,
			State:  memState,
			Type:   memType,
			Offset: dataOffset,
			IsPE:   isMZ,
		})
	}

	if len(curChunks) > 0 {
		d.Regions = append(d.Regions, coalesce(curChunks))
	}
	return nil
}

func coalesce(chunks []Chunk) Region {
	if len(chunks) == 0 {
		return Region{}
	}
	r := Region{
		Start:  chunks[0].Start,
		End:    chunks[len(chunks)-1].End,
		Prot:   chunks[0].Prot,
		IsPE:   chunks[0].IsPE,
		Chunks: chunks,
	}
	r.Size = r.End - r.Start
	// Mixed protections → 0
	for _, c := range chunks[1:] {
		if c.Prot != r.Prot {
			r.Prot = 0
			break
		}
	}
	return r
}

// GetData reads size bytes starting at virtual address addr.
// Returns nil if addr is not mapped in this dump.
func (d *Dump) GetData(addr uint64, size uint32) []byte {
	for _, region := range d.Regions {
		if addr < region.Start || addr >= region.End {
			continue
		}
		for _, chunk := range region.Chunks {
			if addr < chunk.Start || addr >= chunk.End {
				continue
			}
			maxSize := uint32(chunk.End - addr)
			if size > maxSize {
				size = maxSize
			}
			d.file.Seek(chunk.Offset+int64(addr-chunk.Start), io.SeekStart)
			buf := make([]byte, size)
			n, _ := io.ReadFull(d.file, buf)
			return buf[:n]
		}
	}
	return nil
}

// GetChunkData reads the full content of a single chunk.
func (d *Dump) GetChunkData(chunk Chunk) []byte {
	d.file.Seek(chunk.Offset, io.SeekStart)
	buf := make([]byte, chunk.Size)
	n, _ := io.ReadFull(d.file, buf)
	return buf[:n]
}

// Search scans all chunks for regex matches and returns results.
// If findAll is true, returns every match; otherwise stops at the first.
type SearchResult struct {
	Match []byte
	Chunk Chunk
	Offset int // offset within chunk data
}

func (d *Dump) Search(pattern *regexp.Regexp, findAll bool) []SearchResult {
	var results []SearchResult
	for _, region := range d.Regions {
		for _, chunk := range region.Chunks {
			data := d.GetChunkData(chunk)
			if findAll {
				for _, loc := range pattern.FindAllIndex(data, -1) {
					results = append(results, SearchResult{
						Match:  data[loc[0]:loc[1]],
						Chunk:  chunk,
						Offset: loc[0],
					})
				}
			} else {
				loc := pattern.FindIndex(data)
				if loc != nil {
					return []SearchResult{{
						Match:  data[loc[0]:loc[1]],
						Chunk:  chunk,
						Offset: loc[0],
					}}
				}
			}
		}
	}
	return results
}

// ProtString converts a Windows memory protection constant to a human-readable string.
func ProtString(prot uint32) string {
	if prot&PageGuard != 0 {
		return "G"
	}
	switch prot & 0xFF {
	case PageNoAccess:
		return "NOACCESS"
	case PageReadOnly:
		return "R"
	case PageReadWrite:
		return "RW"
	case PageWriteCopy:
		return "RWC"
	case PageExecute:
		return "X"
	case PageExecuteRead:
		return "RX"
	case PageExecuteReadWrite:
		return "RWX"
	case PageExecuteWriteCopy:
		return "RWXC"
	}
	return "UNKNOWN"
}

// IsExecutable returns true if the protection flags include execute permission.
func IsExecutable(prot uint32) bool {
	p := prot & 0xFF
	return p == PageExecute || p == PageExecuteRead ||
		p == PageExecuteReadWrite || p == PageExecuteWriteCopy
}

// IsWritable returns true if the protection flags include write permission.
func IsWritable(prot uint32) bool {
	p := prot & 0xFF
	return p == PageReadWrite || p == PageWriteCopy ||
		p == PageExecuteReadWrite || p == PageExecuteWriteCopy
}
