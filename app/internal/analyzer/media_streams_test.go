package analyzer

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/alirezarajaee/callquality-ai/app/internal/pcap"
)

func buildMediaUDPData(
	t *testing.T,
	sourceIP net.IP,
	destinationIP net.IP,
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
		SrcIP:    sourceIP,
		DstIP:    destinationIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(sourcePort),
		DstPort: layers.UDPPort(destinationPort),
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

func buildMediaSIPMessage(
	startLine string,
	callID string,
	cSeq string,
	from string,
	to string,
	contentType string,
	body string,
) []byte {
	contentLength := len(body)

	return []byte(
		startLine + "\r\n" +
			"Via: SIP/2.0/UDP 10.0.0.10:5060\r\n" +
			"From: " + from + "\r\n" +
			"To: " + to + "\r\n" +
			"Call-ID: " + callID + "\r\n" +
			"CSeq: " + cSeq + "\r\n" +
			"Content-Type: " + contentType + "\r\n" +
			"Content-Length: " +
			itoa(contentLength) +
			"\r\n" +
			"\r\n" +
			body,
	)
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}

	digits := make([]byte, 0, 10)

	for value > 0 {
		digits = append(
			digits,
			byte('0'+value%10),
		)

		value /= 10
	}

	for left, right := 0, len(digits)-1; left < right; left, right = left+1, right-1 {
		digits[left], digits[right] =
			digits[right], digits[left]
	}

	return string(digits)
}

func buildTestRTPPayload(
	sequence uint16,
	timestamp uint32,
	ssrc uint32,
	payload []byte,
) []byte {
	data := make([]byte, 12+len(payload))

	data[0] = 0x80
	data[1] = 0

	binary.BigEndian.PutUint16(
		data[2:4],
		sequence,
	)

	binary.BigEndian.PutUint32(
		data[4:8],
		timestamp,
	)

	binary.BigEndian.PutUint32(
		data[8:12],
		ssrc,
	)

	copy(data[12:], payload)

	return data
}

func createRTPAssociationPCAP(
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

	callID := "rtp-association-001@example.com"

	inviteSDP :=
		"v=0\r\n" +
			"o=- 1 1 IN IP4 10.0.0.10\r\n" +
			"s=CallQuality Test\r\n" +
			"c=IN IP4 10.0.0.10\r\n" +
			"t=0 0\r\n" +
			"m=audio 4000 RTP/AVP 0\r\n" +
			"a=rtpmap:0 PCMU/8000\r\n"

	okSDP :=
		"v=0\r\n" +
			"o=- 2 2 IN IP4 10.0.0.20\r\n" +
			"s=CallQuality Test\r\n" +
			"c=IN IP4 10.0.0.20\r\n" +
			"t=0 0\r\n" +
			"m=audio 5000 RTP/AVP 0\r\n" +
			"a=rtpmap:0 PCMU/8000\r\n"

	messages := []struct {
		sourceIP      net.IP
		destinationIP net.IP
		sourcePort    uint16
		destPort      uint16
		payload       []byte
		timestamp     time.Time
	}{
		{
			sourceIP:      net.IPv4(10, 0, 0, 10),
			destinationIP: net.IPv4(10, 0, 0, 20),
			sourcePort:    5060,
			destPort:      5060,
			payload: buildMediaSIPMessage(
				"INVITE sip:alice@example.com SIP/2.0",
				callID,
				"1 INVITE",
				"<sip:bob@example.com>;tag=from123",
				"<sip:alice@example.com>",
				"application/sdp",
				inviteSDP,
			),
			timestamp: time.Unix(1700000000, 0),
		},
		{
			sourceIP:      net.IPv4(10, 0, 0, 20),
			destinationIP: net.IPv4(10, 0, 0, 10),
			sourcePort:    5060,
			destPort:      5060,
			payload: buildMediaSIPMessage(
				"SIP/2.0 200 OK",
				callID,
				"1 INVITE",
				"<sip:bob@example.com>;tag=from123",
				"<sip:alice@example.com>;tag=to456",
				"application/sdp",
				okSDP,
			),
			timestamp: time.Unix(1700000004, 0),
		},
		{
			sourceIP:      net.IPv4(10, 0, 0, 10),
			destinationIP: net.IPv4(10, 0, 0, 20),
			sourcePort:    5060,
			destPort:      5060,
			payload: buildMediaSIPMessage(
				"ACK sip:alice@example.com SIP/2.0",
				callID,
				"1 ACK",
				"<sip:bob@example.com>;tag=from123",
				"<sip:alice@example.com>;tag=to456",
				"text/plain",
				"",
			),
			timestamp: time.Unix(1700000004, 100_000_000),
		},
	}

	for _, message := range messages {
		data := buildMediaUDPData(
			t,
			message.sourceIP,
			message.destinationIP,
			message.sourcePort,
			message.destPort,
			message.payload,
		)

		info := gopacket.CaptureInfo{
			Timestamp:     message.timestamp,
			CaptureLength: len(data),
			Length:        len(data),
		}

		if err := writer.WritePacket(info, data); err != nil {
			t.Fatalf(
				"write signaling packet: %v",
				err,
			)
		}
	}

	ssrcA := uint32(0x11111111)
	ssrcB := uint32(0x22222222)

	for index, sequence := range []uint16{
		100,
		101,
		103,
		104,
	} {
		rtpPayload := buildTestRTPPayload(
			sequence,
			uint32(sequence)*160,
			ssrcA,
			[]byte{
				0x01,
				0x02,
				0x03,
				0x04,
			},
		)

		data := buildMediaUDPData(
			t,
			net.IPv4(10, 0, 0, 10),
			net.IPv4(10, 0, 0, 20),
			4000,
			5000,
			rtpPayload,
		)

		info := gopacket.CaptureInfo{
			Timestamp: time.Unix(
				1700000005+int64(index),
				0,
			),
			CaptureLength: len(data),
			Length:        len(data),
		}

		if err := writer.WritePacket(info, data); err != nil {
			t.Fatalf(
				"write forward RTP packet: %v",
				err,
			)
		}
	}

	for index, sequence := range []uint16{
		200,
		201,
		202,
	} {
		rtpPayload := buildTestRTPPayload(
			sequence,
			uint32(sequence)*160,
			ssrcB,
			[]byte{
				0x05,
				0x06,
				0x07,
				0x08,
			},
		)

		data := buildMediaUDPData(
			t,
			net.IPv4(10, 0, 0, 20),
			net.IPv4(10, 0, 0, 10),
			5000,
			4000,
			rtpPayload,
		)

		info := gopacket.CaptureInfo{
			Timestamp: time.Unix(
				1700000005+int64(index),
				500_000_000,
			),
			CaptureLength: len(data),
			Length:        len(data),
		}

		if err := writer.WritePacket(info, data); err != nil {
			t.Fatalf(
				"write reverse RTP packet: %v",
				err,
			)
		}
	}

	bye := buildMediaSIPMessage(
		"BYE sip:bob@example.com SIP/2.0",
		callID,
		"2 BYE",
		"<sip:alice@example.com>;tag=to456",
		"<sip:bob@example.com>;tag=from123",
		"text/plain",
		"",
	)

	byeData := buildMediaUDPData(
		t,
		net.IPv4(10, 0, 0, 20),
		net.IPv4(10, 0, 0, 10),
		5060,
		5060,
		bye,
	)

	byeInfo := gopacket.CaptureInfo{
		Timestamp:     time.Unix(1700000015, 0),
		CaptureLength: len(byeData),
		Length:        len(byeData),
	}

	if err := writer.WritePacket(
		byeInfo,
		byeData,
	); err != nil {
		t.Fatalf(
			"write BYE packet: %v",
			err,
		)
	}
}

func TestAttachRTPStreams(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"rtp-association.pcap",
	)

	createRTPAssociationPCAP(t, path)

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
			"expected 1 call, got %d",
			len(calls),
		)
	}

	call := calls[0]

	if len(call.MediaEndpoints) != 2 {
		t.Fatalf(
			"expected 2 media endpoints, got %d",
			len(call.MediaEndpoints),
		)
	}

	callsWithRTP := AttachRTPStreams(
		calls,
		packets,
	)

	if len(callsWithRTP) != 1 {
		t.Fatalf(
			"expected 1 call after RTP association, got %d",
			len(callsWithRTP),
		)
	}

	call = callsWithRTP[0]

	if len(call.RTPStreams) != 2 {
		t.Fatalf(
			"expected 2 RTP streams, got %d",
			len(call.RTPStreams),
		)
	}

	var forward RTPStreamResult
	var reverse RTPStreamResult

	for _, stream := range call.RTPStreams {
		switch stream.Key.SSRC {
		case 0x11111111:
			forward = stream

		case 0x22222222:
			reverse = stream
		}
	}

	if forward.Key.SSRC != 0x11111111 {
		t.Fatal("forward RTP stream was not found")
	}

	if reverse.Key.SSRC != 0x22222222 {
		t.Fatal("reverse RTP stream was not found")
	}

	if forward.Key.SourceIP != "10.0.0.10" {
		t.Fatalf(
			"unexpected forward source IP: %q",
			forward.Key.SourceIP,
		)
	}

	if forward.Key.DestinationIP != "10.0.0.20" {
		t.Fatalf(
			"unexpected forward destination IP: %q",
			forward.Key.DestinationIP,
		)
	}

	if forward.Key.SourcePort != 4000 {
		t.Fatalf(
			"unexpected forward source port: %d",
			forward.Key.SourcePort,
		)
	}

	if forward.Key.DestinationPort != 5000 {
		t.Fatalf(
			"unexpected forward destination port: %d",
			forward.Key.DestinationPort,
		)
	}

	if forward.PayloadType != 0 {
		t.Fatalf(
			"expected forward payload type 0, got %d",
			forward.PayloadType,
		)
	}

	if forward.Stats.PacketCount != 4 {
		t.Fatalf(
			"expected 4 forward RTP packets, got %d",
			forward.Stats.PacketCount,
		)
	}

	if forward.Stats.ExpectedPackets != 5 {
		t.Fatalf(
			"expected 5 forward packets in sequence, got %d",
			forward.Stats.ExpectedPackets,
		)
	}

	if forward.Stats.LostPackets != 1 {
		t.Fatalf(
			"expected 1 forward lost packet, got %d",
			forward.Stats.LostPackets,
		)
	}

	if forward.Stats.LossPercent != 20 {
		t.Fatalf(
			"expected 20%% forward loss, got %.2f%%",
			forward.Stats.LossPercent,
		)
	}

	if reverse.Stats.PacketCount != 3 {
		t.Fatalf(
			"expected 3 reverse RTP packets, got %d",
			reverse.Stats.PacketCount,
		)
	}

	if reverse.Stats.LostPackets != 0 {
		t.Fatalf(
			"expected no reverse packet loss, got %d",
			reverse.Stats.LostPackets,
		)
	}

	if reverse.Stats.LossPercent != 0 {
		t.Fatalf(
			"expected 0%% reverse loss, got %.2f%%",
			reverse.Stats.LossPercent,
		)
	}
}

func TestAttachRTPStreamsIgnoresUnknownPayloadType(t *testing.T) {
	call := Call{
		CallID: "payload-test",
		StartTime: time.Unix(1700000000, 0),
		EndTime: time.Unix(1700000010, 0),
		MediaEndpoints: []MediaEndpoint{
			{
				MediaType:     "audio",
				Address:       "10.0.0.10",
				Port:          4000,
				PortCount:     1,
				Protocol:      "RTP/AVP",
				PayloadTypes:  []int{0},
			},
		},
	}

	rtpPayload := buildTestRTPPayload(
		100,
		16000,
		0x33333333,
		[]byte{1, 2, 3, 4},
	)

	packet := AnalyzedPacket{
		Packet: pcap.DecodedCapturePacket{
			Number:    1,
			Timestamp: time.Unix(1700000005, 0),
			DecodedPacket: pcap.DecodedPacket{
				HasUDP:           true,
				SourceIP:         "10.0.0.10",
				DestinationIP:    "10.0.0.20",
				SourcePort:      4000,
				DestinationPort: 5000,
				Payload:         rtpPayload,
			},
		},
	}

	// Payload Type is 96, while SDP only allows PT 0.
	rtpPayload[1] = 96

	result := AttachRTPStreams(
		[]Call{call},
		[]AnalyzedPacket{packet},
	)

	if len(result) != 1 {
		t.Fatalf(
			"expected 1 call, got %d",
			len(result),
		)
	}

	if len(result[0].RTPStreams) != 0 {
		t.Fatalf(
			"expected 0 RTP streams for unknown payload type, got %d",
			len(result[0].RTPStreams),
		)
	}
}