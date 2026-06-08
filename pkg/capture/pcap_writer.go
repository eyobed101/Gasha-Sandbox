// Package capture implements PCAP file writing for network traffic observed
// during sandbox analysis. It uses gopacket/pcapgo — pure Go, no libpcap.
//
// Usage:
//
//	w, err := capture.NewWriter(jobID, reportsDir, maxSizeMB)
//	defer w.Close()
//	w.WritePacket(ci, data)   // from raw socket / ETW / eBPF network events
package capture

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/lemas-sandbox/lemas/pkg/logger"
)

// PCAPWriter writes captured packets to a .pcap file, respecting a max-size cap.
type PCAPWriter struct {
	mu       sync.Mutex
	file     *os.File
	writer   *pcapgo.Writer
	path     string
	written  int64
	maxBytes int64
	log      interface{ Info() interface{ Msg(string) }  } // zerolog compat shim
}

// NewWriter creates a new pcap file at reports/<jobID>/capture.pcap.
// maxSizeMB == 0 means no cap.
func NewWriter(jobID, reportsDir string, maxSizeMB int) (*PCAPWriter, error) {
	dir := filepath.Join(reportsDir, jobID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("capture: mkdir %s: %w", dir, err)
	}

	path := filepath.Join(dir, "capture.pcap")
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("capture: create %s: %w", path, err)
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		f.Close()
		return nil, fmt.Errorf("capture: write pcap header: %w", err)
	}

	var maxBytes int64
	if maxSizeMB > 0 {
		maxBytes = int64(maxSizeMB) * 1024 * 1024
	}

	return &PCAPWriter{
		file:     f,
		writer:   w,
		path:     path,
		maxBytes: maxBytes,
	}, nil
}

// WritePacket appends a raw packet to the pcap file.
// data should be a full Ethernet frame; if you only have IP, prepend a synthetic header.
func (pw *PCAPWriter) WritePacket(ts time.Time, data []byte) error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.file == nil {
		return nil // already closed
	}
	if pw.maxBytes > 0 && pw.written >= pw.maxBytes {
		return nil // cap reached — silently drop
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(data),
		Length:        len(data),
	}
	if err := pw.writer.WritePacket(ci, data); err != nil {
		return fmt.Errorf("capture: write packet: %w", err)
	}
	pw.written += int64(len(data))
	return nil
}

// WriteSyntheticTCPPacket synthesises a minimal Ethernet+IP+TCP frame from the
// address info available in LEMAS network events and writes it to the pcap.
// This lets analysts open the pcap in Wireshark even when raw frames are unavailable.
func (pw *PCAPWriter) WriteSyntheticTCPPacket(
	ts time.Time,
	srcIP, dstIP string,
	srcPort, dstPort int,
	payload []byte,
) error {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	if ip.SrcIP == nil {
		ip.SrcIP = net.IPv4(127, 0, 0, 1).To4()
	}
	if ip.DstIP == nil {
		ip.DstIP = net.IPv4(0, 0, 0, 0).To4()
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	var pl gopacket.Payload = payload
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, pl); err != nil {
		return err
	}
	return pw.WritePacket(ts, buf.Bytes())
}

// Path returns the absolute path to the pcap file.
func (pw *PCAPWriter) Path() string { return pw.path }

// Written returns how many bytes have been written so far.
func (pw *PCAPWriter) Written() int64 {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	return pw.written
}

// Close flushes and closes the underlying file.
func (pw *PCAPWriter) Close() error {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.file == nil {
		return nil
	}
	log := logger.ForComponent("capture")
	log.Info().Str("path", pw.path).Int64("bytes", pw.written).Msg("pcap capture closed")
	err := pw.file.Close()
	pw.file = nil
	return err
}
