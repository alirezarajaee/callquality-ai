package rtcp

import (
	"encoding/binary"
	"testing"
)

func buildRTCPPacket(
	packetType uint8,
	count uint8,
	body []byte,
) []byte {
	packetLength := 4 + len(body)

	if packetLength%4 != 0 {
		panic("RTCP test packet must be 32-bit aligned")
	}

	data := make([]byte, packetLength)

	data[0] = 0x80 | (count & 0x1F)
	data[1] = packetType

	lengthWords := uint16(
		packetLength/4 - 1,
	)

	binary.BigEndian.PutUint16(
		data[2:4],
		lengthWords,
	)

	copy(data[4:], body)

	return data
}

func buildSenderReport(
	t *testing.T,
) []byte {
	t.Helper()

	body := make([]byte, 48)

	// Sender SSRC
	binary.BigEndian.PutUint32(
		body[0:4],
		0x11223344,
	)

	// NTP timestamp
	binary.BigEndian.PutUint32(
		body[4:8],
		123456789,
	)

	binary.BigEndian.PutUint32(
		body[8:12],
		0xABCDEF01,
	)

	// RTP timestamp
	binary.BigEndian.PutUint32(
		body[12:16],
		987654321,
	)

	// Sender packet count
	binary.BigEndian.PutUint32(
		body[16:20],
		54321,
	)

	// Sender octet count
	binary.BigEndian.PutUint32(
		body[20:24],
		1234567,
	)

	// Report block
	report := body[24:48]

	binary.BigEndian.PutUint32(
		report[0:4],
		0x55667788,
	)

	// Fraction lost = 25 / 256
	report[4] = 25

	// Cumulative packets lost = -3
	report[5] = 0xFF
	report[6] = 0xFF
	report[7] = 0xFD

	// Highest sequence number received
	binary.BigEndian.PutUint32(
		report[8:12],
		0x01020304,
	)

	// Interarrival jitter
	binary.BigEndian.PutUint32(
		report[12:16],
		4321,
	)

	// Last Sender Report
	binary.BigEndian.PutUint32(
		report[16:20],
		0xAABBCCDD,
	)

	// Delay since Last Sender Report
	binary.BigEndian.PutUint32(
		report[20:24],
		0x11223344,
	)

	return buildRTCPPacket(
		packetTypeSenderReport,
		1,
		body,
	)
}

func buildReceiverReport(
	t *testing.T,
) []byte {
	t.Helper()

	body := make([]byte, 28)

	// Receiver SSRC
	binary.BigEndian.PutUint32(
		body[0:4],
		0xCAFEBABE,
	)

	report := body[4:28]

	// Reported source SSRC
	binary.BigEndian.PutUint32(
		report[0:4],
		0x01010101,
	)

	report[4] = 12

	// Cumulative packets lost = 7
	report[5] = 0x00
	report[6] = 0x00
	report[7] = 0x07

	binary.BigEndian.PutUint32(
		report[8:12],
		9000,
	)

	binary.BigEndian.PutUint32(
		report[12:16],
		300,
	)

	binary.BigEndian.PutUint32(
		report[16:20],
		0x12345678,
	)

	binary.BigEndian.PutUint32(
		report[20:24],
		0x00010000,
	)

	return buildRTCPPacket(
		packetTypeReceiverReport,
		1,
		body,
	)
}

func TestParseSenderReport(t *testing.T) {
	data := buildSenderReport(t)

	packets, err := ParseCompound(data)
	if err != nil {
		t.Fatalf(
			"ParseCompound() error = %v",
			err,
		)
	}

	if len(packets) != 1 {
		t.Fatalf(
			"expected 1 packet, got %d",
			len(packets),
		)
	}

	packet := packets[0]

	if packet.Version != 2 {
		t.Fatalf(
			"expected version 2, got %d",
			packet.Version,
		)
	}

	if packet.PacketType != packetTypeSenderReport {
		t.Fatalf(
			"expected packet type %d, got %d",
			packetTypeSenderReport,
			packet.PacketType,
		)
	}

	if packet.Count != 1 {
		t.Fatalf(
			"expected report count 1, got %d",
			packet.Count,
		)
	}

	if packet.SSRC != 0x11223344 {
		t.Fatalf(
			"unexpected sender SSRC: %#x",
			packet.SSRC,
		)
	}

	if packet.SenderInfo == nil {
		t.Fatal("expected SenderInfo")
	}

	if packet.SenderInfo.NTPSeconds != 123456789 {
		t.Fatalf(
			"unexpected NTP seconds: %d",
			packet.SenderInfo.NTPSeconds,
		)
	}

	if packet.SenderInfo.NTPFraction != 0xABCDEF01 {
		t.Fatalf(
			"unexpected NTP fraction: %#x",
			packet.SenderInfo.NTPFraction,
		)
	}

	if packet.SenderInfo.RTPTimestamp != 987654321 {
		t.Fatalf(
			"unexpected RTP timestamp: %d",
			packet.SenderInfo.RTPTimestamp,
		)
	}

	if packet.SenderInfo.SenderPacketCount != 54321 {
		t.Fatalf(
			"unexpected sender packet count: %d",
			packet.SenderInfo.SenderPacketCount,
		)
	}

	if packet.SenderInfo.SenderOctetCount != 1234567 {
		t.Fatalf(
			"unexpected sender octet count: %d",
			packet.SenderInfo.SenderOctetCount,
		)
	}

	if len(packet.ReportBlocks) != 1 {
		t.Fatalf(
			"expected 1 report block, got %d",
			len(packet.ReportBlocks),
		)
	}

	report := packet.ReportBlocks[0]

	if report.SSRC != 0x55667788 {
		t.Fatalf(
			"unexpected report SSRC: %#x",
			report.SSRC,
		)
	}

	if report.FractionLost != 25 {
		t.Fatalf(
			"expected fraction lost 25, got %d",
			report.FractionLost,
		)
	}

	if report.CumulativePacketsLost != -3 {
		t.Fatalf(
			"expected cumulative lost -3, got %d",
			report.CumulativePacketsLost,
		)
	}

	if report.HighestSequenceNumber != 0x01020304 {
		t.Fatalf(
			"unexpected highest sequence number: %#x",
			report.HighestSequenceNumber,
		)
	}

	if report.Jitter != 4321 {
		t.Fatalf(
			"unexpected jitter: %d",
			report.Jitter,
		)
	}

	if report.LastSenderReport != 0xAABBCCDD {
		t.Fatalf(
			"unexpected LSR: %#x",
			report.LastSenderReport,
		)
	}

	if report.DelaySinceLastSenderReport != 0x11223344 {
		t.Fatalf(
			"unexpected DLSR: %#x",
			report.DelaySinceLastSenderReport,
		)
	}
}

func TestParseReceiverReport(t *testing.T) {
	data := buildReceiverReport(t)

	packets, err := ParseCompound(data)
	if err != nil {
		t.Fatalf(
			"ParseCompound() error = %v",
			err,
		)
	}

	if len(packets) != 1 {
		t.Fatalf(
			"expected 1 packet, got %d",
			len(packets),
		)
	}

	packet := packets[0]

	if packet.PacketType != packetTypeReceiverReport {
		t.Fatalf(
			"expected RR packet type %d, got %d",
			packetTypeReceiverReport,
			packet.PacketType,
		)
	}

	if packet.SSRC != 0xCAFEBABE {
		t.Fatalf(
			"unexpected receiver SSRC: %#x",
			packet.SSRC,
		)
	}

	if packet.SenderInfo != nil {
		t.Fatal(
			"Receiver Report must not contain SenderInfo",
		)
	}

	if len(packet.ReportBlocks) != 1 {
		t.Fatalf(
			"expected 1 report block, got %d",
			len(packet.ReportBlocks),
		)
	}

	report := packet.ReportBlocks[0]

	if report.SSRC != 0x01010101 {
		t.Fatalf(
			"unexpected report SSRC: %#x",
			report.SSRC,
		)
	}

	if report.FractionLost != 12 {
		t.Fatalf(
			"expected fraction lost 12, got %d",
			report.FractionLost,
		)
	}

	if report.CumulativePacketsLost != 7 {
		t.Fatalf(
			"expected cumulative lost 7, got %d",
			report.CumulativePacketsLost,
		)
	}

	if report.HighestSequenceNumber != 9000 {
		t.Fatalf(
			"expected highest sequence 9000, got %d",
			report.HighestSequenceNumber,
		)
	}

	if report.Jitter != 300 {
		t.Fatalf(
			"expected jitter 300, got %d",
			report.Jitter,
		)
	}

	if report.LastSenderReport != 0x12345678 {
		t.Fatalf(
			"unexpected LSR: %#x",
			report.LastSenderReport,
		)
	}

	if report.DelaySinceLastSenderReport != 0x00010000 {
		t.Fatalf(
			"unexpected DLSR: %#x",
			report.DelaySinceLastSenderReport,
		)
	}
}

func TestParseCompoundRTCP(t *testing.T) {
	senderReport := buildSenderReport(t)
	receiverReport := buildReceiverReport(t)

	data := append(
		senderReport,
		receiverReport...,
	)

	packets, err := ParseCompound(data)
	if err != nil {
		t.Fatalf(
			"ParseCompound() error = %v",
			err,
		)
	}

	if len(packets) != 2 {
		t.Fatalf(
			"expected 2 RTCP packets, got %d",
			len(packets),
		)
	}

	if packets[0].PacketType != packetTypeSenderReport {
		t.Fatalf(
			"expected first packet to be SR, got %d",
			packets[0].PacketType,
		)
	}

	if packets[1].PacketType != packetTypeReceiverReport {
		t.Fatalf(
			"expected second packet to be RR, got %d",
			packets[1].PacketType,
		)
	}
}

func TestParseUnknownRTCPPacket(t *testing.T) {
	body := make([]byte, 4)

	binary.BigEndian.PutUint32(
		body,
		0x12345678,
	)

	data := buildRTCPPacket(
		202,
		0,
		body,
	)

	packets, err := ParseCompound(data)
	if err != nil {
		t.Fatalf(
			"ParseCompound() error = %v",
			err,
		)
	}

	if len(packets) != 1 {
		t.Fatalf(
			"expected 1 packet, got %d",
			len(packets),
		)
	}

	if packets[0].PacketType != 202 {
		t.Fatalf(
			"expected packet type 202, got %d",
			packets[0].PacketType,
		)
	}

	if packets[0].SenderInfo != nil {
		t.Fatal(
			"unknown RTCP packet must not create SenderInfo",
		)
	}
}

func TestRejectTruncatedRTCPHeader(t *testing.T) {
	_, err := ParseCompound([]byte{
		0x80,
		200,
		0x00,
	})

	if err == nil {
		t.Fatal(
			"expected truncated RTCP header error",
		)
	}
}

func TestRejectTruncatedRTCPPacket(t *testing.T) {
	data := []byte{
		0x80,
		200,
		0x00,
		0x05,
		0x00,
		0x00,
		0x00,
		0x00,
	}

	_, err := ParseCompound(data)

	if err == nil {
		t.Fatal(
			"expected truncated RTCP packet error",
		)
	}
}

func TestRejectWrongRTCPVersion(t *testing.T) {
	data := buildReceiverReport(t)

	data[0] = 0x40

	_, err := ParseCompound(data)

	if err == nil {
		t.Fatal(
			"expected wrong RTCP version error",
		)
	}
}