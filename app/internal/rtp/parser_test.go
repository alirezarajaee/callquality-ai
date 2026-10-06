package rtp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func buildBasicRTPPacket() []byte {
	payload := []byte("audio-payload")

	data := make([]byte, 12+len(payload))

	// RTP Version = 2
	data[0] = 0x80

	// Payload Type = 0
	data[1] = 0x00

	// Sequence Number = 1000
	binary.BigEndian.PutUint16(data[2:4], 1000)

	// Timestamp = 160
	binary.BigEndian.PutUint32(data[4:8], 160)

	// SSRC = 0x11223344
	binary.BigEndian.PutUint32(data[8:12], 0x11223344)

	copy(data[12:], payload)

	return data
}

func TestParseBasicPacket(t *testing.T) {
	data := buildBasicRTPPacket()

	packet, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if packet.Version != 2 {
		t.Fatalf(
			"expected version 2, got %d",
			packet.Version,
		)
	}

	if packet.Padding {
		t.Fatal("did not expect padding")
	}

	if packet.Extension {
		t.Fatal("did not expect extension")
	}

	if packet.CSRCCount != 0 {
		t.Fatalf(
			"expected zero CSRC entries, got %d",
			packet.CSRCCount,
		)
	}

	if packet.Marker {
		t.Fatal("did not expect marker bit")
	}

	if packet.PayloadType != 0 {
		t.Fatalf(
			"expected payload type 0, got %d",
			packet.PayloadType,
		)
	}

	if packet.SequenceNumber != 1000 {
		t.Fatalf(
			"expected sequence number 1000, got %d",
			packet.SequenceNumber,
		)
	}

	if packet.Timestamp != 160 {
		t.Fatalf(
			"expected timestamp 160, got %d",
			packet.Timestamp,
		)
	}

	if packet.SSRC != 0x11223344 {
		t.Fatalf(
			"unexpected SSRC: %#x",
			packet.SSRC,
		)
	}

	if packet.HeaderLength != 12 {
		t.Fatalf(
			"expected header length 12, got %d",
			packet.HeaderLength,
		)
	}

	if packet.PayloadLength != len("audio-payload") {
		t.Fatalf(
			"unexpected payload length: %d",
			packet.PayloadLength,
		)
	}

	if !bytes.Equal(
		packet.Payload,
		[]byte("audio-payload"),
	) {
		t.Fatalf(
			"unexpected payload: %q",
			packet.Payload,
		)
	}
}

func TestParseMarkerAndDynamicPayloadType(t *testing.T) {
	data := buildBasicRTPPacket()

	// Marker = 1
	// Payload Type = 96
	data[1] = 0x80 | 96

	packet, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if !packet.Marker {
		t.Fatal("expected marker bit")
	}

	if packet.PayloadType != 96 {
		t.Fatalf(
			"expected payload type 96, got %d",
			packet.PayloadType,
		)
	}
}

func TestParseCSRC(t *testing.T) {
	payload := []byte("data")

	data := make([]byte, 12+8+len(payload))

	// Version 2, CSRC count = 2
	data[0] = 0x82
	data[1] = 0x00

	binary.BigEndian.PutUint16(data[2:4], 10)
	binary.BigEndian.PutUint32(data[4:8], 20)
	binary.BigEndian.PutUint32(data[8:12], 0xAABBCCDD)

	// Two CSRC identifiers
	binary.BigEndian.PutUint32(data[12:16], 0x01020304)
	binary.BigEndian.PutUint32(data[16:20], 0x05060708)

	copy(data[20:], payload)

	packet, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if packet.CSRCCount != 2 {
		t.Fatalf(
			"expected 2 CSRC entries, got %d",
			packet.CSRCCount,
		)
	}

	if packet.HeaderLength != 20 {
		t.Fatalf(
			"expected header length 20, got %d",
			packet.HeaderLength,
		)
	}

	if packet.PayloadLength != len(payload) {
		t.Fatalf(
			"unexpected payload length: %d",
			packet.PayloadLength,
		)
	}

	if !bytes.Equal(packet.Payload, payload) {
		t.Fatalf(
			"unexpected payload: %q",
			packet.Payload,
		)
	}
}

func TestParseExtension(t *testing.T) {
	payload := []byte("opus-data")

	// 12-byte fixed header
	// 4-byte extension header
	// 4-byte extension data
	// payload
	data := make([]byte, 12+4+4+len(payload))

	// Version 2 + Extension bit
	data[0] = 0x90

	// Marker + dynamic payload type 96
	data[1] = 0x80 | 96

	binary.BigEndian.PutUint16(data[2:4], 500)
	binary.BigEndian.PutUint32(data[4:8], 960)
	binary.BigEndian.PutUint32(data[8:12], 0xCAFEBABE)

	// Extension profile
	binary.BigEndian.PutUint16(data[12:14], 0xBEDE)

	// Extension length = 1 word = 4 bytes
	binary.BigEndian.PutUint16(data[14:16], 1)

	// Extension data
	copy(
		data[16:20],
		[]byte{0x01, 0x02, 0x03, 0x04},
	)

	copy(data[20:], payload)

	packet, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if !packet.Extension {
		t.Fatal("expected extension flag")
	}

	if packet.HeaderLength != 20 {
		t.Fatalf(
			"expected header length 20, got %d",
			packet.HeaderLength,
		)
	}

	if packet.PayloadType != 96 {
		t.Fatalf(
			"expected payload type 96, got %d",
			packet.PayloadType,
		)
	}

	if packet.SequenceNumber != 500 {
		t.Fatalf(
			"expected sequence number 500, got %d",
			packet.SequenceNumber,
		)
	}

	if packet.Timestamp != 960 {
		t.Fatalf(
			"expected timestamp 960, got %d",
			packet.Timestamp,
		)
	}

	if packet.SSRC != 0xCAFEBABE {
		t.Fatalf(
			"unexpected SSRC: %#x",
			packet.SSRC,
		)
	}

	if !bytes.Equal(packet.Payload, payload) {
		t.Fatalf(
			"unexpected payload: %q",
			packet.Payload,
		)
	}
}

func TestParsePadding(t *testing.T) {
	payload := []byte("audio")

	data := make([]byte, 12+len(payload)+4)

	// Version 2 + Padding bit
	data[0] = 0xA0
	data[1] = 0

	binary.BigEndian.PutUint16(data[2:4], 200)
	binary.BigEndian.PutUint32(data[4:8], 320)
	binary.BigEndian.PutUint32(data[8:12], 0x12345678)

	copy(data[12:], payload)

	// Four padding bytes.
	data[len(data)-4] = 0
	data[len(data)-3] = 0
	data[len(data)-2] = 0
	data[len(data)-1] = 4

	packet, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if !packet.Padding {
		t.Fatal("expected padding flag")
	}

	if !bytes.Equal(packet.Payload, payload) {
		t.Fatalf(
			"unexpected payload after padding removal: %q",
			packet.Payload,
		)
	}

	if packet.PayloadLength != len(payload) {
		t.Fatalf(
			"expected payload length %d, got %d",
			len(payload),
			packet.PayloadLength,
		)
	}
}

func TestRejectShortPacket(t *testing.T) {
	_, err := Parse(make([]byte, 11))

	if err == nil {
		t.Fatal("expected short packet error")
	}
}

func TestRejectWrongVersion(t *testing.T) {
	data := buildBasicRTPPacket()

	// Version 1
	data[0] = 0x40

	_, err := Parse(data)

	if err == nil {
		t.Fatal("expected unsupported RTP version error")
	}
}

func TestRejectTruncatedCSRC(t *testing.T) {
	data := make([]byte, 13)

	// Version 2 + CSRC count 1
	data[0] = 0x81

	_, err := Parse(data)

	if err == nil {
		t.Fatal("expected truncated CSRC error")
	}
}

func TestRejectTruncatedExtension(t *testing.T) {
	data := make([]byte, 14)

	// Version 2 + extension bit
	data[0] = 0x90

	_, err := Parse(data)

	if err == nil {
		t.Fatal("expected truncated extension error")
	}
}

func TestRejectInvalidPadding(t *testing.T) {
	data := buildBasicRTPPacket()

	// Version 2 + padding bit
	data[0] = 0xA0

	// Padding claims more bytes than exist.
	data[len(data)-1] = 100

	_, err := Parse(data)

	if err == nil {
		t.Fatal("expected invalid padding error")
	}
}