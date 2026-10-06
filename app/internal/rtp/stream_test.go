package rtp

import (
	"math"
	"testing"
	"time"
)

func testRTPPacket(sequence uint16) Packet {
	return Packet{
		Version:        2,
		PayloadType:    0,
		SequenceNumber: sequence,
		Timestamp:      uint32(sequence) * 160,
		SSRC:           0x11223344,
		HeaderLength:   12,
		PayloadLength:  10,
	}
}

func TestStreamDetectsPacketLoss(t *testing.T) {
	stream := NewStream(StreamKey{
		SSRC:            0x11223344,
		SourceIP:        "192.168.1.10",
		DestinationIP:   "192.168.1.20",
		SourcePort:      4000,
		DestinationPort: 5000,
	})

	sequences := []uint16{
		1000,
		1001,
		1003,
		1004,
	}

	baseTime := time.Unix(1700000000, 0)

	for index, sequence := range sequences {
		packet := testRTPPacket(sequence)
		packet.Timestamp = uint32(index) * 160

		stream.Add(
			packet,
			baseTime.Add(
				time.Duration(index)*20*time.Millisecond,
			),
		)
	}

	stats := stream.Stats()

	if stats.PacketCount != 4 {
		t.Fatalf(
			"expected 4 packets, got %d",
			stats.PacketCount,
		)
	}

	if stats.UniquePackets != 4 {
		t.Fatalf(
			"expected 4 unique packets, got %d",
			stats.UniquePackets,
		)
	}

	if stats.ExpectedPackets != 5 {
		t.Fatalf(
			"expected 5 expected packets, got %d",
			stats.ExpectedPackets,
		)
	}

	if stats.LostPackets != 1 {
		t.Fatalf(
			"expected 1 lost packet, got %d",
			stats.LostPackets,
		)
	}

	if stats.LossPercent != 20 {
		t.Fatalf(
			"expected 20%% loss, got %.2f%%",
			stats.LossPercent,
		)
	}
}

func TestStreamDetectsOutOfOrderPacket(t *testing.T) {
	stream := NewStream(StreamKey{
		SSRC: 0x11223344,
	})

	sequences := []uint16{
		1000,
		1001,
		1003,
		1002,
	}

	for index, sequence := range sequences {
		packet := testRTPPacket(sequence)
		packet.Timestamp = uint32(index) * 160

		stream.Add(
			packet,
			time.Unix(
				1700000000+int64(index),
				0,
			),
		)
	}

	stats := stream.Stats()

	if stats.LostPackets != 0 {
		t.Fatalf(
			"expected no lost packets, got %d",
			stats.LostPackets,
		)
	}

	if stats.OutOfOrderPackets != 1 {
		t.Fatalf(
			"expected 1 out-of-order packet, got %d",
			stats.OutOfOrderPackets,
		)
	}
}

func TestStreamDetectsDuplicatePacket(t *testing.T) {
	stream := NewStream(StreamKey{
		SSRC: 0x11223344,
	})

	sequences := []uint16{
		1000,
		1001,
		1001,
		1002,
	}

	for index, sequence := range sequences {
		packet := testRTPPacket(sequence)
		packet.Timestamp = uint32(index) * 160

		stream.Add(
			packet,
			time.Unix(
				1700000000+int64(index),
				0,
			),
		)
	}

	stats := stream.Stats()

	if stats.PacketCount != 4 {
		t.Fatalf(
			"expected 4 packets, got %d",
			stats.PacketCount,
		)
	}

	if stats.UniquePackets != 3 {
		t.Fatalf(
			"expected 3 unique packets, got %d",
			stats.UniquePackets,
		)
	}

	if stats.DuplicatePackets != 1 {
		t.Fatalf(
			"expected 1 duplicate packet, got %d",
			stats.DuplicatePackets,
		)
	}

	if stats.LostPackets != 0 {
		t.Fatalf(
			"expected no lost packets, got %d",
			stats.LostPackets,
		)
	}
}

func TestStreamHandlesSequenceWrapAround(t *testing.T) {
	stream := NewStream(StreamKey{
		SSRC: 0x11223344,
	})

	sequences := []uint16{
		65534,
		65535,
		0,
		1,
		2,
	}

	for index, sequence := range sequences {
		packet := testRTPPacket(sequence)
		packet.Timestamp = uint32(index) * 160

		stream.Add(
			packet,
			time.Unix(
				1700000000+int64(index),
				0,
			),
		)
	}

	stats := stream.Stats()

	if stats.ExpectedPackets != 5 {
		t.Fatalf(
			"expected 5 expected packets, got %d",
			stats.ExpectedPackets,
		)
	}

	if stats.UniquePackets != 5 {
		t.Fatalf(
			"expected 5 unique packets, got %d",
			stats.UniquePackets,
		)
	}

	if stats.LostPackets != 0 {
		t.Fatalf(
			"expected 0 lost packets, got %d",
			stats.LostPackets,
		)
	}
}

func TestStreamIncludesJitter(t *testing.T) {
	stream := NewStream(StreamKey{
		SSRC: 0x11223344,
	})

	if err := stream.ConfigureJitter(8000); err != nil {
		t.Fatalf(
			"ConfigureJitter() error = %v",
			err,
		)
	}

	baseTime := time.Unix(1700000000, 0)

	packets := []struct {
		sequence  uint16
		timestamp uint32
		arrival   time.Time
	}{
		{
			sequence:  1000,
			timestamp: 0,
			arrival:   baseTime,
		},
		{
			sequence:  1001,
			timestamp: 160,
			arrival:   baseTime.Add(20 * time.Millisecond),
		},
		{
			sequence:  1002,
			timestamp: 320,
			arrival:   baseTime.Add(60 * time.Millisecond),
		},
		{
			sequence:  1003,
			timestamp: 480,
			arrival:   baseTime.Add(80 * time.Millisecond),
		},
	}

	for _, item := range packets {
		packet := testRTPPacket(item.sequence)
		packet.Timestamp = item.timestamp

		stream.Add(
			packet,
			item.arrival,
		)
	}

	stats := stream.Stats()

	if !stats.JitterAvailable {
		t.Fatal("expected jitter to be available")
	}

	if stats.JitterClockRate != 8000 {
		t.Fatalf(
			"expected jitter clock rate 8000, got %d",
			stats.JitterClockRate,
		)
	}

	expectedUnits := 19.375

	if math.Abs(
		stats.JitterTimestampUnits-expectedUnits,
	) > 0.0001 {
		t.Fatalf(
			"expected jitter %.4f units, got %.4f",
			expectedUnits,
			stats.JitterTimestampUnits,
		)
	}

	expectedMilliseconds := 2.421875

	if math.Abs(
		stats.JitterMilliseconds-expectedMilliseconds,
	) > 0.000001 {
		t.Fatalf(
			"expected jitter %.6f ms, got %.6f",
			expectedMilliseconds,
			stats.JitterMilliseconds,
		)
	}
}

func TestStreamJitterRequiresClockRateConfiguration(t *testing.T) {
	stream := NewStream(StreamKey{
		SSRC: 0x11223344,
	})

	baseTime := time.Unix(1700000000, 0)

	first := testRTPPacket(1000)
	first.Timestamp = 0

	second := testRTPPacket(1001)
	second.Timestamp = 160

	stream.Add(first, baseTime)

	stream.Add(
		second,
		baseTime.Add(20*time.Millisecond),
	)

	stats := stream.Stats()

	if stats.JitterAvailable {
		t.Fatal(
			"expected jitter to be unavailable without clock rate",
		)
	}
}

func TestEmptyStream(t *testing.T) {
	stream := NewStream(StreamKey{
		SSRC: 0x11223344,
	})

	stats := stream.Stats()

	if stats.PacketCount != 0 {
		t.Fatalf(
			"expected 0 packets, got %d",
			stats.PacketCount,
		)
	}

	if stats.UniquePackets != 0 {
		t.Fatalf(
			"expected 0 unique packets, got %d",
			stats.UniquePackets,
		)
	}

	if stats.ExpectedPackets != 0 {
		t.Fatalf(
			"expected 0 expected packets, got %d",
			stats.ExpectedPackets,
		)
	}

	if stats.LostPackets != 0 {
		t.Fatalf(
			"expected 0 lost packets, got %d",
			stats.LostPackets,
		)
	}

	if stats.LossPercent != 0 {
		t.Fatalf(
			"expected 0%% loss, got %.2f%%",
			stats.LossPercent,
		)
	}

	if stats.JitterAvailable {
		t.Fatal("did not expect jitter to be available")
	}
}