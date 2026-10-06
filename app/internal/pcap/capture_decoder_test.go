package pcap

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func netMAC(values ...byte) net.HardwareAddr {
	return net.HardwareAddr(values)
}

func netIP(a, b, c, d byte) net.IP {
	return net.IPv4(a, b, c, d)
}

func createDecodedTestPCAP(t *testing.T, path string) {
	t.Helper()

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create test pcap: %v", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)

	if err := writer.WriteFileHeader(
		65535,
		layers.LinkTypeEthernet,
	); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       netMAC(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
		DstMAC:       netMAC(0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb),
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    netIP(192, 168, 1, 10),
		DstIP:    netIP(192, 168, 1, 20),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 5000,
		DstPort: 5060,
	}

	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set UDP checksum layer: %v", err)
	}

	payload := gopacket.Payload(
		[]byte("INVITE sip:test@example.com SIP/2.0\r\n"),
	)

	buffer := gopacket.NewSerializeBuffer()

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(
		buffer,
		options,
		ethernet,
		ip,
		udp,
		payload,
	); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	baseTime := time.Unix(1700000000, 0)

	for i := 0; i < 3; i++ {
		data := buffer.Bytes()

		captureInfo := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(time.Duration(i) * time.Second),
			CaptureLength: len(data),
			Length:        len(data),
		}

		if err := writer.WritePacket(captureInfo, data); err != nil {
			t.Fatalf("write packet %d: %v", i+1, err)
		}
	}
}

func TestReadAndDecodeFile(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"decoded-test.pcap",
	)

	createDecodedTestPCAP(t, path)

	summary, packets, err := ReadAndDecodeFile(path)
	if err != nil {
		t.Fatalf("ReadAndDecodeFile() error = %v", err)
	}

	if summary.PacketCount != 3 {
		t.Fatalf(
			"expected 3 packets, got %d",
			summary.PacketCount,
		)
	}

	if len(packets) != 3 {
		t.Fatalf(
			"expected 3 decoded packets, got %d",
			len(packets),
		)
	}

	if summary.IPv4Packets != 3 {
		t.Fatalf(
			"expected 3 IPv4 packets, got %d",
			summary.IPv4Packets,
		)
	}

	if summary.UDPPackets != 3 {
		t.Fatalf(
			"expected 3 UDP packets, got %d",
			summary.UDPPackets,
		)
	}

	if summary.TCPPackets != 0 {
		t.Fatalf(
			"expected 0 TCP packets, got %d",
			summary.TCPPackets,
		)
	}

	first := packets[0].DecodedPacket

	if first.SourceIP != "192.168.1.10" {
		t.Fatalf(
			"unexpected source IP: %q",
			first.SourceIP,
		)
	}

	if first.DestinationIP != "192.168.1.20" {
		t.Fatalf(
			"unexpected destination IP: %q",
			first.DestinationIP,
		)
	}

	if first.SourcePort != 5000 {
		t.Fatalf(
			"unexpected source port: %d",
			first.SourcePort,
		)
	}

	if first.DestinationPort != 5060 {
		t.Fatalf(
			"unexpected destination port: %d",
			first.DestinationPort,
		)
	}

	if first.TransportProtocol != "UDP" {
		t.Fatalf(
			"unexpected transport protocol: %q",
			first.TransportProtocol,
		)

	}

	if summary.Duration != 2*time.Second {
		t.Fatalf(
			"expected duration 2s, got %v",
			summary.Duration,
		)
	}
}