package rtcp

import (
	"math"
	"testing"
	"time"
)

func TestCorrelatorMatchesRRToSenderReport(t *testing.T) {
	baseTime := time.Date(
		2026,
		1,
		1,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	const (
		senderSSRC   = uint32(0x11223344)
		receiverSSRC = uint32(0x55667788)

		ntpSeconds  = uint32(0x12345678)
		ntpFraction = uint32(0x9abcdef0)
	)

	lsr := NTPShort(
		ntpSeconds,
		ntpFraction,
	)

	correlator := NewCorrelator()

	senderReport := Packet{
		PacketType: packetTypeSenderReport,
		SSRC:       senderSSRC,
		SenderInfo: &SenderInfo{
			NTPSeconds:        ntpSeconds,
			NTPFraction:       ntpFraction,
			RTPTimestamp:      123456,
			SenderPacketCount: 1000,
			SenderOctetCount:  160000,
		},
	}

	observations := correlator.Observe(
		baseTime,
		senderReport,
		8000,
	)

	if len(observations) != 0 {
		t.Fatalf(
			"expected no observations from SR without report blocks, got %d",
			len(observations),
		)
	}

	// DLSR uses 1/65536-second units.
	// 22938 units is approximately 350 milliseconds.
	dlsr := uint32(22938)

	receiverReportTime := baseTime.Add(
		1*time.Second + 350*time.Millisecond,
	)

	receiverReport := Packet{
		PacketType: packetTypeReceiverReport,
		SSRC:       receiverSSRC,
		ReportBlocks: []ReportBlock{
			{
				SSRC:                       senderSSRC,
				FractionLost:               32,
				CumulativePacketsLost:      4,
				HighestSequenceNumber:      1200,
				Jitter:                     80,
				LastSenderReport:           lsr,
				DelaySinceLastSenderReport: dlsr,
			},
		},
	}

	observations = correlator.Observe(
		receiverReportTime,
		receiverReport,
		8000,
	)

	if len(observations) != 1 {
		t.Fatalf(
			"expected one observation, got %d",
			len(observations),
		)
	}

	observation := observations[0]

	if observation.ReporterSSRC != receiverSSRC {
		t.Fatalf(
			"reporter SSRC mismatch: got 0x%08x want 0x%08x",
			observation.ReporterSSRC,
			receiverSSRC,
		)
	}

	if observation.TargetSSRC != senderSSRC {
		t.Fatalf(
			"target SSRC mismatch: got 0x%08x want 0x%08x",
			observation.TargetSSRC,
			senderSSRC,
		)
	}

	if observation.Metrics.CumulativePacketsLost != 4 {
		t.Fatalf(
			"cumulative loss mismatch: got %d want 4",
			observation.Metrics.CumulativePacketsLost,
		)
	}

	if math.Abs(
		observation.Metrics.FractionLostPercent-12.5,
	) > 1e-12 {
		t.Fatalf(
			"fraction lost mismatch: got %.12f want 12.5",
			observation.Metrics.FractionLostPercent,
		)
	}

	if math.Abs(
		observation.Metrics.JitterMilliseconds-10,
	) > 1e-12 {
		t.Fatalf(
			"jitter mismatch: got %.12f want 10",
			observation.Metrics.JitterMilliseconds,
		)
	}

	if !observation.PassiveRTTAvailable {
		t.Fatal("expected passive RTT to be available")
	}

	// The capture interval is approximately 1.350 seconds and
	// DLSR is approximately 0.350 seconds, leaving approximately
	// 1.000 second of observed round-trip time.
	if math.Abs(
		observation.PassiveRTTSeconds-1.0,
	) > 0.002 {
		t.Fatalf(
			"passive RTT mismatch: got %.6f want approximately 1.0",
			observation.PassiveRTTSeconds,
		)
	}
}

func TestCorrelatorWithoutMatchingSenderReport(t *testing.T) {
	correlator := NewCorrelator()

	report := Packet{
		PacketType: packetTypeReceiverReport,
		SSRC:       0x55667788,
		ReportBlocks: []ReportBlock{
			{
				SSRC:                       0x11223344,
				FractionLost:               64,
				Jitter:                     160,
				LastSenderReport:           0x01020304,
				DelaySinceLastSenderReport: 65536,
			},
		},
	}

	observations := correlator.Observe(
		time.Date(
			2026,
			1,
			1,
			12,
			0,
			2,
			0,
			time.UTC,
		),
		report,
		8000,
	)

	if len(observations) != 1 {
		t.Fatalf(
			"expected one observation, got %d",
			len(observations),
		)
	}

	if observations[0].PassiveRTTAvailable {
		t.Fatal(
			"expected passive RTT to be unavailable without a matching SR",
		)
	}
}

func TestCorrelatorSupportsUnknownClockRate(t *testing.T) {
	correlator := NewCorrelator()

	report := Packet{
		PacketType: packetTypeReceiverReport,
		SSRC:       0x55667788,
		ReportBlocks: []ReportBlock{
			{
				SSRC:         0x11223344,
				FractionLost: 128,
				Jitter:       480,
			},
		},
	}

	observations := correlator.Observe(
		time.Date(
			2026,
			1,
			1,
			12,
			0,
			0,
			0,
			time.UTC,
		),
		report,
		0,
	)

	if len(observations) != 1 {
		t.Fatalf(
			"expected one observation, got %d",
			len(observations),
		)
	}

	if observations[0].Metrics.JitterAvailable {
		t.Fatal("expected jitter conversion to be unavailable")
	}

	if observations[0].Metrics.JitterMilliseconds != 0 {
		t.Fatalf(
			"expected zero jitter milliseconds, got %.12f",
			observations[0].Metrics.JitterMilliseconds,
		)
	}
}

func TestCorrelatorKeepsRecentSenderReports(t *testing.T) {
	correlator := NewCorrelator()

	const senderSSRC = uint32(0x12345678)

	baseTime := time.Date(
		2026,
		1,
		1,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	for i := 0; i < maxStoredSenderReports+3; i++ {
		senderReport := Packet{
			PacketType: packetTypeSenderReport,
			SSRC:       senderSSRC,
			SenderInfo: &SenderInfo{
				NTPSeconds:  uint32(i + 1),
				NTPFraction: 0,
			},
		}

		correlator.Observe(
			baseTime.Add(
				time.Duration(i)*time.Second,
			),
			senderReport,
			8000,
		)
	}

	if len(
		correlator.senderReports[senderSSRC],
	) != maxStoredSenderReports {
		t.Fatalf(
			"unexpected stored SR count: got %d want %d",
			len(correlator.senderReports[senderSSRC]),
			maxStoredSenderReports,
		)
	}
}
