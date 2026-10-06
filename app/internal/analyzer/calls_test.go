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

func buildCallTestPacket(
	t *testing.T,
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
		SrcPort: 5060,
		DstPort: 5060,
	}

	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf(
			"set UDP checksum layer: %v",
			err,
		)
	}

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
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf(
			"serialize packet: %v",
			err,
		)
	}

	return buffer.Bytes()
}

func createCallTestPCAP(
	t *testing.T,
	path string,
) {
	t.Helper()

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf(
			"create test pcap: %v",
			err,
		)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)

	if err := writer.WriteFileHeader(
		65535,
		layers.LinkTypeEthernet,
	); err != nil {
		t.Fatalf(
			"write pcap header: %v",
			err,
		)
	}

	messages := [][]byte{
		[]byte(
			"INVITE sip:alice@example.com SIP/2.0\r\n" +
				"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" +
				"From: <sip:bob@example.com>;tag=from123\r\n" +
				"To: <sip:alice@example.com>\r\n" +
				"Call-ID: call-reconstruct-001@example.com\r\n" +
				"CSeq: 1 INVITE\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
		),

		[]byte(
			"SIP/2.0 180 Ringing\r\n" +
				"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" +
				"From: <sip:bob@example.com>;tag=from123\r\n" +
				"To: <sip:alice@example.com>;tag=to456\r\n" +
				"Call-ID: call-reconstruct-001@example.com\r\n" +
				"CSeq: 1 INVITE\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
		),

		[]byte(
			"SIP/2.0 200 OK\r\n" +
				"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" +
				"From: <sip:bob@example.com>;tag=from123\r\n" +
				"To: <sip:alice@example.com>;tag=to456\r\n" +
				"Call-ID: call-reconstruct-001@example.com\r\n" +
				"CSeq: 1 INVITE\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
		),

		[]byte(
			"ACK sip:alice@example.com SIP/2.0\r\n" +
				"Via: SIP/2.0/UDP 192.168.1.10:5060\r\n" +
				"From: <sip:bob@example.com>;tag=from123\r\n" +
				"To: <sip:alice@example.com>;tag=to456\r\n" +
				"Call-ID: call-reconstruct-001@example.com\r\n" +
				"CSeq: 1 ACK\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
		),

		[]byte(
			"BYE sip:bob@example.com SIP/2.0\r\n" +
				"Via: SIP/2.0/UDP 192.168.1.20:5060\r\n" +
				"From: <sip:alice@example.com>;tag=to456\r\n" +
				"To: <sip:bob@example.com>;tag=from123\r\n" +
				"Call-ID: call-reconstruct-001@example.com\r\n" +
				"CSeq: 2 BYE\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
		),
	}

	timestamps := []time.Time{
		time.Unix(1700000000, 0),
		time.Unix(1700000002, 0),
		time.Unix(1700000004, 0),
		time.Unix(1700000004, 100_000_000),
		time.Unix(1700000059, 0),
	}

	for i, message := range messages {
		data := buildCallTestPacket(t, message)

		info := gopacket.CaptureInfo{
			Timestamp:     timestamps[i],
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

func TestReconstructCalls(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"call-reconstruction.pcap",
	)

	createCallTestPCAP(t, path)

	_, packets, err := AnalyzeFile(path)
	if err != nil {
		t.Fatalf(
			"AnalyzeFile() error = %v",
			err,
		)
	}

	calls := ReconstructCalls(packets)

	if len(calls) != 1 {
		t.Fatalf(
			"expected 1 reconstructed call, got %d",
			len(calls),
		)
	}

	call := calls[0]

	if call.CallID != "call-reconstruct-001@example.com" {
		t.Fatalf(
			"unexpected Call-ID: %q",
			call.CallID,
		)
	}

	if !call.HasInvite {
		t.Fatal("expected INVITE")
	}

	if !call.HasRinging {
		t.Fatal("expected 180 Ringing")
	}

	if !call.HasOK {
		t.Fatal("expected 200 OK")
	}

	if !call.HasACK {
		t.Fatal("expected ACK")
	}

	if !call.HasBYE {
		t.Fatal("expected BYE")
	}

	if call.State != CallStateCompleted {
		t.Fatalf(
			"expected COMPLETED state, got %s",
			call.State,
		)
	}

	expectedSetup := 4 * time.Second

	if call.SetupDuration != expectedSetup {
		t.Fatalf(
			"expected setup duration %v, got %v",
			expectedSetup,
			call.SetupDuration,
		)
	}

	expectedDuration := 55 * time.Second

	if call.Duration != expectedDuration {
		t.Fatalf(
			"expected call duration %v, got %v",
			expectedDuration,
			call.Duration,
		)
	}

	if len(call.Messages) != 5 {
		t.Fatalf(
			"expected 5 signaling events, got %d",
			len(call.Messages),
		)
	}
}