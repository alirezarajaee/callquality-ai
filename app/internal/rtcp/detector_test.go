package rtcp

import (
	"encoding/binary"
	"testing"
)

func buildDetectorRTCPPacket(
	packetType uint8,
	count uint8,
	body []byte,
) []byte {
	const headerLen = 4

	totalLen := headerLen + len(body)

	if totalLen%4 != 0 {
		panic("RTCP detector test packet must be 32-bit aligned")
	}

	lengthWords := uint16(totalLen/4 - 1)

	packet := make([]byte, totalLen)

	packet[0] = byte(rtcpVersion << 6)
	packet[0] |= count & 0x1f
	packet[1] = packetType

	binary.BigEndian.PutUint16(
		packet[2:4],
		lengthWords,
	)

	copy(packet[4:], body)

	return packet
}

func TestDetectSenderReport(t *testing.T) {
	body := make([]byte, 24)

	binary.BigEndian.PutUint32(
		body[0:4],
		0x11223344,
	)

	packet := buildDetectorRTCPPacket(
		packetTypeSenderReport,
		0,
		body,
	)

	result := Detect(packet)

	if !result.IsRTCP {
		t.Fatal("expected packet to be detected as RTCP")
	}

	if result.PacketCount != 1 {
		t.Fatalf(
			"packet count mismatch: got %d want 1",
			result.PacketCount,
		)
	}

	if len(result.PacketTypes) != 1 {
		t.Fatalf(
			"packet type count mismatch: got %d want 1",
			len(result.PacketTypes),
		)
	}

	if result.PacketTypes[0] != packetTypeSenderReport {
		t.Fatalf(
			"packet type mismatch: got %d want %d",
			result.PacketTypes[0],
			packetTypeSenderReport,
		)
	}

	if !result.HasSenderReport {
		t.Fatal("expected HasSenderReport=true")
	}

	if result.HasReceiverReport {
		t.Fatal("expected HasReceiverReport=false")
	}
}

func TestDetectReceiverReport(t *testing.T) {
	body := make([]byte, 4)

	binary.BigEndian.PutUint32(
		body[0:4],
		0x55667788,
	)

	packet := buildDetectorRTCPPacket(
		packetTypeReceiverReport,
		0,
		body,
	)

	result := Detect(packet)

	if !result.IsRTCP {
		t.Fatal("expected packet to be detected as RTCP")
	}

	if result.PacketCount != 1 {
		t.Fatalf(
			"packet count mismatch: got %d want 1",
			result.PacketCount,
		)
	}

	if len(result.PacketTypes) != 1 {
		t.Fatalf(
			"packet type count mismatch: got %d want 1",
			len(result.PacketTypes),
		)
	}

	if result.PacketTypes[0] != packetTypeReceiverReport {
		t.Fatalf(
			"packet type mismatch: got %d want %d",
			result.PacketTypes[0],
			packetTypeReceiverReport,
		)
	}

	if result.HasSenderReport {
		t.Fatal("expected HasSenderReport=false")
	}

	if !result.HasReceiverReport {
		t.Fatal("expected HasReceiverReport=true")
	}
}

func TestDetectCompoundRTCP(t *testing.T) {
	senderBody := make([]byte, 24)

	binary.BigEndian.PutUint32(
		senderBody[0:4],
		0x11111111,
	)

	receiverBody := make([]byte, 4)

	binary.BigEndian.PutUint32(
		receiverBody[0:4],
		0x22222222,
	)

	sender := buildDetectorRTCPPacket(
		packetTypeSenderReport,
		0,
		senderBody,
	)

	receiver := buildDetectorRTCPPacket(
		packetTypeReceiverReport,
		0,
		receiverBody,
	)

	compound := append(
		sender,
		receiver...,
	)

	result := Detect(compound)

	if !result.IsRTCP {
		t.Fatal("expected compound packet to be detected as RTCP")
	}

	if result.PacketCount != 2 {
		t.Fatalf(
			"packet count mismatch: got %d want 2",
			result.PacketCount,
		)
	}

	if len(result.PacketTypes) != 2 {
		t.Fatalf(
			"packet type count mismatch: got %d want 2",
			len(result.PacketTypes),
		)
	}

	if result.PacketTypes[0] != packetTypeSenderReport {
		t.Fatalf(
			"first packet type mismatch: got %d want %d",
			result.PacketTypes[0],
			packetTypeSenderReport,
		)
	}

	if result.PacketTypes[1] != packetTypeReceiverReport {
		t.Fatalf(
			"second packet type mismatch: got %d want %d",
			result.PacketTypes[1],
			packetTypeReceiverReport,
		)
	}

	if !result.HasSenderReport {
		t.Fatal("expected HasSenderReport=true")
	}

	if !result.HasReceiverReport {
		t.Fatal("expected HasReceiverReport=true")
	}
}

func TestDetectCommonUnknownRTCPType(t *testing.T) {
	// 202 is SDES, which is valid RTCP but not fully parsed into
	// semantic fields by the current RTCP parser.
	body := make([]byte, 4)

	packet := buildDetectorRTCPPacket(
		202,
		0,
		body,
	)

	result := Detect(packet)

	if !result.IsRTCP {
		t.Fatal("expected SDES packet to be detected as RTCP")
	}

	if result.PacketCount != 1 {
		t.Fatalf(
			"packet count mismatch: got %d want 1",
			result.PacketCount,
		)
	}

	if len(result.PacketTypes) != 1 ||
		result.PacketTypes[0] != 202 {
		t.Fatalf(
			"unexpected packet types: %#v",
			result.PacketTypes,
		)
	}
}

func TestDetectRejectsEmptyPayload(t *testing.T) {
	result := Detect(nil)

	if result.IsRTCP {
		t.Fatal("empty payload must not be detected as RTCP")
	}

	if result.PacketCount != 0 {
		t.Fatalf(
			"expected zero packet count, got %d",
			result.PacketCount,
		)
	}

	if len(result.PacketTypes) != 0 {
		t.Fatalf(
			"expected no packet types, got %#v",
			result.PacketTypes,
		)
	}
}

func TestDetectRejectsTruncatedPayload(t *testing.T) {
	packet := []byte{
		byte(rtcpVersion << 6),
		packetTypeSenderReport,
		0x00,
		0x06,
	}

	result := Detect(packet)

	if result.IsRTCP {
		t.Fatal("truncated payload must not be detected as RTCP")
	}
}

func TestDetectRejectsWrongVersion(t *testing.T) {
	body := make([]byte, 4)

	packet := buildDetectorRTCPPacket(
		packetTypeReceiverReport,
		0,
		body,
	)

	packet[0] = 0x40

	result := Detect(packet)

	if result.IsRTCP {
		t.Fatal("wrong RTCP version must not be detected")
	}
}

func TestDetectRejectsTypicalRTPPacket(t *testing.T) {
	// RTP v2, marker not set, static payload type 0 (PCMU).
	// It has an RTP header but not an RTCP packet type.
	rtp := make([]byte, 12)

	rtp[0] = 0x80
	rtp[1] = 0x00

	binary.BigEndian.PutUint16(
		rtp[2:4],
		100,
	)

	binary.BigEndian.PutUint32(
		rtp[4:8],
		160,
	)

	binary.BigEndian.PutUint32(
		rtp[8:12],
		0x12345678,
	)

	result := Detect(rtp)

	if result.IsRTCP {
		t.Fatal("typical RTP packet must not be detected as RTCP")
	}

	if IsRTCP(rtp) {
		t.Fatal("IsRTCP must reject a typical RTP packet")
	}
}

func TestIsRTCPWrapper(t *testing.T) {
	body := make([]byte, 4)

	packet := buildDetectorRTCPPacket(
		packetTypeReceiverReport,
		0,
		body,
	)

	if !IsRTCP(packet) {
		t.Fatal("expected IsRTCP to return true")
	}
}
