package analyzer

import (
	"math"
	"testing"
	"time"

	"github.com/alirezarajaee/callquality-ai/app/internal/rtcp"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
)

func TestBuildUnifiedMediaMetrics(t *testing.T) {
	const (
		callID = "call-001"
		ssrc   = uint32(0x11223344)
	)

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

	streamKey := rtp.StreamKey{
		SSRC:            ssrc,
		SourceIP:        "10.10.0.1",
		DestinationIP:   "10.10.0.2",
		SourcePort:      10000,
		DestinationPort: 20000,
	}

	stream := RTPStreamResult{
		Key:         streamKey,
		PayloadType: 0,
		Stats: rtp.StreamStats{
			Key:                  streamKey,
			PacketCount:          100,
			UniquePackets:        98,
			DuplicatePackets:     1,
			OutOfOrderPackets:    1,
			FirstSequence:        1000,
			LastSequence:         1099,
			FirstTimestamp:       16000,
			LastTimestamp:        31840,
			ExpectedPackets:      100,
			LostPackets:          2,
			LossPercent:          2.0,
			JitterAvailable:      true,
			JitterClockRate:      8000,
			JitterTimestampUnits: 80,
			JitterMilliseconds:   10,
		},
	}

	calls := []Call{
		{
			CallID: "call-001",
			RTPStreams: []RTPStreamResult{
				stream,
			},
		},
	}

	rtcpResults := []RTCPStreamResult{
		{
			CallID:      callID,
			Key:         streamKey,
			PayloadType: 0,
			ReportObservations: []rtcp.ReportObservation{
				{
					CapturedAt:   baseTime,
					ReporterSSRC: 0x55667788,
					TargetSSRC:   ssrc,
					Metrics: rtcp.ReportMetrics{
						FractionLostPercent:     4.0,
						CumulativePacketsLost:   4,
						JitterTimestampUnits:    80,
						JitterMilliseconds:      0,
						JitterAvailable:         false,
						DelaySinceLastSRSeconds: 0,
					},
					PassiveRTTSeconds:   0.080,
					PassiveRTTAvailable: true,
				},
				{
					CapturedAt:   baseTime.Add(2 * time.Second),
					ReporterSSRC: 0x55667788,
					TargetSSRC:   ssrc,
					Metrics: rtcp.ReportMetrics{
						FractionLostPercent:     8.0,
						CumulativePacketsLost:   9,
						JitterTimestampUnits:    120,
						JitterMilliseconds:      0,
						JitterAvailable:         false,
						DelaySinceLastSRSeconds: 0,
					},
					PassiveRTTSeconds:   0.120,
					PassiveRTTAvailable: true,
				},
			},
		},
	}

	results := BuildUnifiedMediaMetrics(
		calls,
		rtcpResults,
	)

	if len(results) != 1 {
		t.Fatalf(
			"result count mismatch: got %d want 1",
			len(results),
		)
	}

	result := results[0]

	if result.CallID != callID {
		t.Fatalf(
			"call ID mismatch: got %q want %q",
			result.CallID,
			callID,
		)
	}

	if result.Key != streamKey {
		t.Fatal("stream key mismatch")
	}

	if result.PayloadType != 0 {
		t.Fatalf(
			"payload type mismatch: got %d want 0",
			result.PayloadType,
		)
	}

	if result.ClockRate != 8000 {
		t.Fatalf(
			"clock rate mismatch: got %d want 8000",
			result.ClockRate,
		)
	}

	if result.RTP.PacketCount != 100 {
		t.Fatalf(
			"RTP packet count mismatch: got %d want 100",
			result.RTP.PacketCount,
		)
	}

	if result.RTP.LostPackets != 2 {
		t.Fatalf(
			"RTP lost packet mismatch: got %d want 2",
			result.RTP.LostPackets,
		)
	}

	if math.Abs(result.RTP.LossPercent-2.0) > 1e-12 {
		t.Fatalf(
			"RTP loss mismatch: got %.12f want 2.0",
			result.RTP.LossPercent,
		)
	}

	if !result.HasRTCP {
		t.Fatal("expected HasRTCP=true")
	}

	if result.RTCPObservationCount != 2 {
		t.Fatalf(
			"RTCP observation count mismatch: got %d want 2",
			result.RTCPObservationCount,
		)
	}

	if math.Abs(
		result.AverageFractionLostPercent-6.0,
	) > 1e-12 {
		t.Fatalf(
			"average RTCP loss mismatch: got %.12f want 6.0",
			result.AverageFractionLostPercent,
		)
	}

	if !result.AverageJitterAvailable {
		t.Fatal("expected average jitter to be available")
	}

	if math.Abs(
		result.AverageJitterMilliseconds-12.5,
	) > 1e-12 {
		t.Fatalf(
			"average jitter mismatch: got %.12f want 12.5",
			result.AverageJitterMilliseconds,
		)
	}

	if !result.AveragePassiveRTTAvailable {
		t.Fatal("expected average RTT to be available")
	}

	if math.Abs(
		result.AveragePassiveRTTSeconds-0.100,
	) > 1e-12 {
		t.Fatalf(
			"average RTT mismatch: got %.12f want 0.100",
			result.AveragePassiveRTTSeconds,
		)
	}

	if !result.LatestRTCPCapturedAt.Equal(
		baseTime.Add(2 * time.Second),
	) {
		t.Fatal("latest RTCP timestamp mismatch")
	}

	if math.Abs(
		result.LatestFractionLostPercent-8.0,
	) > 1e-12 {
		t.Fatalf(
			"latest loss mismatch: got %.12f want 8.0",
			result.LatestFractionLostPercent,
		)
	}

	if result.LatestCumulativeLost != 9 {
		t.Fatalf(
			"latest cumulative loss mismatch: got %d want 9",
			result.LatestCumulativeLost,
		)
	}

	if result.LatestJitterTimestampUnits != 120 {
		t.Fatalf(
			"latest jitter units mismatch: got %d want 120",
			result.LatestJitterTimestampUnits,
		)
	}

	if math.Abs(
		result.LatestJitterMilliseconds-15,
	) > 1e-12 {
		t.Fatalf(
			"latest jitter mismatch: got %.12f want 15",
			result.LatestJitterMilliseconds,
		)
	}

	if !result.LatestPassiveRTTAvailable {
		t.Fatal("expected latest RTT to be available")
	}

	if math.Abs(
		result.LatestPassiveRTTSeconds-0.120,
	) > 1e-12 {
		t.Fatalf(
			"latest RTT mismatch: got %.12f want 0.120",
			result.LatestPassiveRTTSeconds,
		)
	}
}

func TestBuildUnifiedMediaMetricsWithoutRTCP(t *testing.T) {
	const (
		callID = "call-no-rtcp"
		ssrc   = uint32(0x12345678)
	)

	streamKey := rtp.StreamKey{
		SSRC:            ssrc,
		SourceIP:        "192.168.1.10",
		DestinationIP:   "192.168.1.20",
		SourcePort:      4000,
		DestinationPort: 5000,
	}

	calls := []Call{
		{
			CallID: callID,
			RTPStreams: []RTPStreamResult{
				{
					Key:         streamKey,
					PayloadType: 0,
					Stats: rtp.StreamStats{
						Key:                  streamKey,
						PacketCount:          50,
						UniquePackets:        50,
						ExpectedPackets:      50,
						LostPackets:          0,
						LossPercent:          0,
						JitterAvailable:      true,
						JitterClockRate:      8000,
						JitterTimestampUnits: 32,
						JitterMilliseconds:   4,
					},
				},
			},
		},
	}

	results := BuildUnifiedMediaMetrics(
		calls,
		nil,
	)

	if len(results) != 1 {
		t.Fatalf(
			"result count mismatch: got %d want 1",
			len(results),
		)
	}

	result := results[0]

	if result.HasRTCP {
		t.Fatal("expected HasRTCP=false")
	}

	if result.RTCPObservationCount != 0 {
		t.Fatalf(
			"expected zero RTCP observations, got %d",
			result.RTCPObservationCount,
		)
	}

	if result.AverageFractionLostPercent != 0 {
		t.Fatalf(
			"expected zero RTCP average loss, got %.12f",
			result.AverageFractionLostPercent,
		)
	}

	if result.AverageJitterAvailable {
		t.Fatal(
			"expected average RTCP jitter to be unavailable",
		)
	}

	if result.AveragePassiveRTTAvailable {
		t.Fatal(
			"expected average RTT to be unavailable",
		)
	}

	if result.RTP.PacketCount != 50 {
		t.Fatalf(
			"RTP packet count mismatch: got %d want 50",
			result.RTP.PacketCount,
		)
	}
}

func TestBuildUnifiedMediaMetricsIgnoresUnmatchedRTCP(t *testing.T) {
	const (
		callID     = "call-001"
		streamSSRC = uint32(0x11111111)
		wrongSSRC  = uint32(0x22222222)
	)

	streamKey := rtp.StreamKey{
		SSRC:            streamSSRC,
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.2",
		SourcePort:      10000,
		DestinationPort: 20000,
	}

	calls := []Call{
		{
			CallID: callID,
			RTPStreams: []RTPStreamResult{
				{
					Key:         streamKey,
					PayloadType: 0,
					Stats: rtp.StreamStats{
						Key:             streamKey,
						PacketCount:     10,
						LostPackets:     0,
						LossPercent:     0,
						ExpectedPackets: 10,
					},
				},
			},
		},
	}

	otherKey := rtp.StreamKey{
		SSRC:            wrongSSRC,
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.2",
		SourcePort:      10000,
		DestinationPort: 20000,
	}

	rtcpResults := []RTCPStreamResult{
		{
			CallID:      callID,
			Key:         otherKey,
			PayloadType: 0,
			ReportObservations: []rtcp.ReportObservation{
				{
					Metrics: rtcp.ReportMetrics{
						FractionLostPercent: 25,
					},
				},
			},
		},
	}

	results := BuildUnifiedMediaMetrics(
		calls,
		rtcpResults,
	)

	if len(results) != 1 {
		t.Fatalf(
			"result count mismatch: got %d want 1",
			len(results),
		)
	}

	if results[0].HasRTCP {
		t.Fatal(
			"wrong RTCP stream must not be attached",
		)
	}

	if results[0].RTCPObservationCount != 0 {
		t.Fatalf(
			"expected zero RTCP observations, got %d",
			results[0].RTCPObservationCount,
		)
	}
}

func TestBuildUnifiedMediaMetricsDoesNotInventRTCPJitterWithoutClockRate(t *testing.T) {
	const (
		callID = "call-no-clock-rate"
		ssrc   = uint32(0x01020304)
	)

	streamKey := rtp.StreamKey{
		SSRC:            ssrc,
		SourceIP:        "10.20.0.1",
		DestinationIP:   "10.20.0.2",
		SourcePort:      10000,
		DestinationPort: 20000,
	}

	calls := []Call{
		{
			CallID: callID,
			RTPStreams: []RTPStreamResult{
				{
					Key:         streamKey,
					PayloadType: 0,
					Stats: rtp.StreamStats{
						Key:                  streamKey,
						PacketCount:          10,
						ExpectedPackets:      10,
						JitterClockRate:      0,
						JitterTimestampUnits: 80,
					},
				},
			},
		},
	}

	rtcpResults := []RTCPStreamResult{
		{
			CallID:      callID,
			Key:         streamKey,
			PayloadType: 0,
			ReportObservations: []rtcp.ReportObservation{
				{
					TargetSSRC: ssrc,
					Metrics: rtcp.ReportMetrics{
						JitterTimestampUnits: 80,
						JitterMilliseconds:   0,
						JitterAvailable:      false,
					},
				},
			},
		},
	}

	results := BuildUnifiedMediaMetrics(calls, rtcpResults)

	if len(results) != 1 {
		t.Fatalf("result count mismatch: got %d want 1", len(results))
	}

	result := results[0]

	if result.AverageJitterAvailable {
		t.Fatal("RTCP jitter must remain unavailable without a clock rate")
	}

	if result.LatestJitterAvailable {
		t.Fatal("latest RTCP jitter must remain unavailable without a clock rate")
	}
}

func TestBuildUnifiedMediaMetricsSupportsMultipleCalls(t *testing.T) {
	callOneKey := rtp.StreamKey{
		SSRC:            0x10000001,
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.2",
		SourcePort:      10000,
		DestinationPort: 20000,
	}

	callTwoKey := rtp.StreamKey{
		SSRC:            0x20000002,
		SourceIP:        "10.0.0.3",
		DestinationIP:   "10.0.0.4",
		SourcePort:      30000,
		DestinationPort: 40000,
	}

	calls := []Call{
		{
			CallID: "call-1",
			RTPStreams: []RTPStreamResult{
				{
					Key:         callOneKey,
					PayloadType: 0,
					Stats: rtp.StreamStats{
						Key:         callOneKey,
						PacketCount: 100,
						LostPackets: 5,
						LossPercent: 5,
					},
				},
			},
		},
		{
			CallID: "call-2",
			RTPStreams: []RTPStreamResult{
				{
					Key:         callTwoKey,
					PayloadType: 111,
					Stats: rtp.StreamStats{
						Key:         callTwoKey,
						PacketCount: 200,
						LostPackets: 2,
						LossPercent: 1,
					},
				},
			},
		},
	}

	results := BuildUnifiedMediaMetrics(
		calls,
		nil,
	)

	if len(results) != 2 {
		t.Fatalf(
			"result count mismatch: got %d want 2",
			len(results),
		)
	}

	if results[0].CallID != "call-1" {
		t.Fatalf(
			"first call mismatch: got %q",
			results[0].CallID,
		)
	}

	if results[1].CallID != "call-2" {
		t.Fatalf(
			"second call mismatch: got %q",
			results[1].CallID,
		)
	}

	if results[0].PayloadType != 0 {
		t.Fatalf(
			"first payload type mismatch: got %d",
			results[0].PayloadType,
		)
	}

	if results[1].PayloadType != 111 {
		t.Fatalf(
			"second payload type mismatch: got %d",
			results[1].PayloadType,
		)
	}
}
