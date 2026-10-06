package analyzer

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

func buildUDPData(
	t *testing.T,
	sourcePort uint16,
	destinationPort uint16,
	payload []byte,
) []byte {
	t.Helper()

	ethernet := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		},
		DstMAC: net.HardwareAddr{
			0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
		},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    net.IPv4(192, 168, 1, 10),
		DstIP:    net.IPv4(192, 168, 1, 20),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(sourcePort),
		DstPort: layers.UDPPort(destinationPort),
	}

	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set UDP checksum layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(
		buffer,
		options,
		ethernet,
		ip,
		udp,
		gopacket.Payload(payload),
	)

	if err != nil {
		t.Fatalf("serialize UDP packet: %v", err)
	}

	return buffer.Bytes()
}

func createAnalyzerTestPCAP(t *testing.T, path string) {
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

	invite := []byte(
		"INVITE sip:alice@example.com SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" +
			"Call-ID: analyzer-test-001\r\n" +
			"CSeq: 1 INVITE\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	)

	okResponse := []byte(
		"SIP/2.0 200 OK\r\n" +
			"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" +
			"Call-ID: analyzer-test-001\r\n" +
			"CSeq: 1 INVITE\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	)

	nonSIP := []byte(
		"GET / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"\r\n",
	)

	ethernetPayloads := []struct {
		sourcePort      uint16
		destinationPort uint16
		payload         []byte
	}{
		{
			sourcePort:      5060,
			destinationPort: 5060,
			payload:         invite,
		},
		{
			sourcePort:      5060,
			destinationPort: 5060,
			payload:         okResponse,
		},
		{
			sourcePort:      40000,
			destinationPort: 8080,
			payload:         nonSIP,
		},
	}

	baseTime := time.Unix(1700000000, 0)

	for i, item := range ethernetPayloads {
		data := buildUDPData(
			t,
			item.sourcePort,
			item.destinationPort,
			item.payload,
		)

		info := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(time.Duration(i) * time.Second),
			CaptureLength: len(data),
			Length:        len(data),
		}

		if err := writer.WritePacket(info, data); err != nil {
			t.Fatalf(
				"write packet %d: %v",
				i+1,
				err,
			)
		}
	}
}

func TestAnalyzeFile(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"analyzer-test.pcap",
	)

	createAnalyzerTestPCAP(t, path)

	summary, packets, err := AnalyzeFile(path)
	if err != nil {
		t.Fatalf(
			"AnalyzeFile() error = %v",
			err,
		)
	}

	if summary.PacketCount != 3 {
		t.Fatalf(
			"expected 3 packets, got %d",
			summary.PacketCount,
		)
	}

	if len(packets) != 3 {
		t.Fatalf(
			"expected 3 analyzed packets, got %d",
			len(packets),
		)
	}

	if summary.SIPPackets != 2 {
		t.Fatalf(
			"expected 2 SIP packets, got %d",
			summary.SIPPackets,
		)
	}

	if summary.SIPRequests != 1 {
		t.Fatalf(
			"expected 1 SIP request, got %d",
			summary.SIPRequests,
		)
	}

	if summary.SIPResponses != 1 {
		t.Fatalf(
			"expected 1 SIP response, got %d",
			summary.SIPResponses,
		)
	}

	if !packets[0].SIP.IsSIP {
		t.Fatal("expected packet 1 to be SIP")
	}

	if packets[0].SIP.Method != "INVITE" {
		t.Fatalf(
			"expected packet 1 method INVITE, got %q",
			packets[0].SIP.Method,
		)
	}

	if !packets[1].SIP.IsSIP {
		t.Fatal("expected packet 2 to be SIP")
	}

	if packets[1].SIP.StatusCode != 200 {
		t.Fatalf(
			"expected packet 2 status 200, got %d",
			packets[1].SIP.StatusCode,
		)
	}

	if packets[2].SIP.IsSIP {
		t.Fatal("expected packet 3 not to be SIP")
	}
}