package features

import (
	"math"
	"testing"
	"time"

	"github.com/alirezarajaee/callquality-ai/app/internal/analyzer"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
)

func TestExtractCallFeatures(t *testing.T) {
	call := analyzer.Call{
		CallID: "call-001",

		SetupDuration: 750 * time.Millisecond,
		Duration:      12 * time.Second,

		FinalResponseCode: 200,

		HasInvite:  true,
		HasRinging: true,
		HasOK:      true,
		HasACK:     true,
		HasBYE:     true,

		RTPStreams: []analyzer.RTPStreamResult{
			{
				Key: rtp.StreamKey{
					SSRC: 0x11111111,
				},
			},
			{
				Key: rtp.StreamKey{
					SSRC: 0x22222222,
				},
			},
		},
	}

	result := ExtractCallFeatures(call)

	if result.SchemaVersion != SchemaVersion {
		t.Fatalf(
			"schema version mismatch: got %q want %q",
			result.SchemaVersion,
			SchemaVersion,
		)
	}

	if result.CallID != "call-001" {
		t.Fatalf(
			"call ID mismatch: got %q",
			result.CallID,
		)
	}

	if math.Abs(
		result.SetupDurationMs-750,
	) > 1e-12 {
		t.Fatalf(
			"setup duration mismatch: got %.12f",
			result.SetupDurationMs,
		)
	}

	if math.Abs(
		result.CallDurationMs-12000,
	) > 1e-12 {
		t.Fatalf(
			"call duration mismatch: got %.12f",
			result.CallDurationMs,
		)
	}

	if result.FinalResponseCode != 200 {
		t.Fatalf(
			"response code mismatch: got %.0f",
			result.FinalResponseCode,
		)
	}

	if result.HasInvite != 1 ||
		result.HasRinging != 1 ||
		result.HasOK != 1 ||
		result.HasACK != 1 ||
		result.HasBYE != 1 {
		t.Fatal("expected all signaling flags to be 1")
	}

	if result.MediaStreamCount != 2 {
		t.Fatalf(
			"media stream count mismatch: got %.0f want 2",
			result.MediaStreamCount,
		)
	}
}

func TestExtractStreamFeatures(t *testing.T) {
	key := rtp.StreamKey{
		SSRC:            0x11223344,
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.2",
		SourcePort:      10000,
		DestinationPort: 20000,
	}

	metrics := analyzer.UnifiedMediaMetrics{
		CallID:      "call-001",
		Key:         key,
		PayloadType: 0,
		ClockRate:   8000,

		RTP: rtp.StreamStats{
			Key:                  key,
			PacketCount:          1000,
			UniquePackets:        990,
			DuplicatePackets:     5,
			OutOfOrderPackets:    5,
			FirstSequence:        1000,
			LastSequence:         1999,
			FirstTimestamp:       16000,
			LastTimestamp:        32000,
			ExpectedPackets:      1000,
			LostPackets:          10,
			LossPercent:          1.0,
			JitterAvailable:      true,
			JitterClockRate:      8000,
			JitterTimestampUnits: 80,
			JitterMilliseconds:   10,
		},

		HasRTCP:              true,
		RTCPObservationCount: 3,

		AverageFractionLostPercent: 2.0,
		LatestFractionLostPercent:  3.0,

		LatestCumulativeLost: 30,

		AverageJitterMilliseconds: 15.0,
		LatestJitterMilliseconds:  18.0,

		AverageJitterAvailable: true,
		LatestJitterAvailable:  true,

		AveragePassiveRTTSeconds: 0.080,
		LatestPassiveRTTSeconds:  0.120,

		AveragePassiveRTTAvailable: true,
		LatestPassiveRTTAvailable:  true,
	}

	result := ExtractStreamFeatures(metrics)

	if result.SchemaVersion != SchemaVersion {
		t.Fatalf(
			"schema version mismatch: got %q want %q",
			result.SchemaVersion,
			SchemaVersion,
		)
	}

	if result.CallID != "call-001" {
		t.Fatalf(
			"call ID mismatch: got %q",
			result.CallID,
		)
	}

	if result.SSRC != key.SSRC {
		t.Fatalf(
			"SSRC mismatch: got 0x%08x want 0x%08x",
			result.SSRC,
			key.SSRC,
		)
	}

	if result.PayloadType != 0 {
		t.Fatalf(
			"payload type mismatch: got %.0f",
			result.PayloadType,
		)
	}

	if result.ClockRate != 8000 {
		t.Fatalf(
			"clock rate mismatch: got %.0f",
			result.ClockRate,
		)
	}

	if result.PacketCount != 1000 {
		t.Fatalf(
			"packet count mismatch: got %.0f",
			result.PacketCount,
		)
	}

	if result.UniquePackets != 990 {
		t.Fatalf(
			"unique packet mismatch: got %.0f",
			result.UniquePackets,
		)
	}

	if result.DuplicatePackets != 5 {
		t.Fatalf(
			"duplicate packet mismatch: got %.0f",
			result.DuplicatePackets,
		)
	}

	if result.OutOfOrderPackets != 5 {
		t.Fatalf(
			"out-of-order packet mismatch: got %.0f",
			result.OutOfOrderPackets,
		)
	}

	if result.ExpectedPackets != 1000 {
		t.Fatalf(
			"expected packet mismatch: got %.0f",
			result.ExpectedPackets,
		)
	}

	if result.LostPackets != 10 {
		t.Fatalf(
			"lost packet mismatch: got %.0f",
			result.LostPackets,
		)
	}

	if math.Abs(
		result.RTPLossPercent-1.0,
	) > 1e-12 {
		t.Fatalf(
			"RTP loss mismatch: got %.12f",
			result.RTPLossPercent,
		)
	}

	if result.RTPJitterAvailable != 1 {
		t.Fatal("expected RTP jitter to be available")
	}

	if math.Abs(
		result.RTPJitterMs-10,
	) > 1e-12 {
		t.Fatalf(
			"RTP jitter mismatch: got %.12f",
			result.RTPJitterMs,
		)
	}

	if result.HasRTCP != 1 {
		t.Fatal("expected HasRTCP=1")
	}

	if result.RTCPObservationCount != 3 {
		t.Fatalf(
			"RTCP observation count mismatch: got %.0f",
			result.RTCPObservationCount,
		)
	}

	if math.Abs(
		result.RTCPLossAveragePercent-2.0,
	) > 1e-12 {
		t.Fatalf(
			"average RTCP loss mismatch: got %.12f",
			result.RTCPLossAveragePercent,
		)
	}

	if math.Abs(
		result.RTCPLossLatestPercent-3.0,
	) > 1e-12 {
		t.Fatalf(
			"latest RTCP loss mismatch: got %.12f",
			result.RTCPLossLatestPercent,
		)
	}

	if result.RTCPCumulativeLost != 30 {
		t.Fatalf(
			"cumulative RTCP loss mismatch: got %.0f",
			result.RTCPCumulativeLost,
		)
	}

	if math.Abs(
		result.RTCPJitterAverageMs-15,
	) > 1e-12 {
		t.Fatalf(
			"average RTCP jitter mismatch: got %.12f",
			result.RTCPJitterAverageMs,
		)
	}

	if math.Abs(
		result.RTCPJitterLatestMs-18,
	) > 1e-12 {
		t.Fatalf(
			"latest RTCP jitter mismatch: got %.12f",
			result.RTCPJitterLatestMs,
		)
	}

	if result.RTCPJitterAvailableAverage != 1 ||
		result.RTCPJitterAvailableLatest != 1 {
		t.Fatal("expected RTCP jitter availability flags to be 1")
	}

	if result.RTTAvailableAverage != 1 ||
		result.RTTAvailableLatest != 1 {
		t.Fatal("expected RTT availability flags to be 1")
	}

	if math.Abs(
		result.RTTAverageMs-80,
	) > 1e-12 {
		t.Fatalf(
			"average RTT mismatch: got %.12f",
			result.RTTAverageMs,
		)
	}

	if math.Abs(
		result.RTTLatestMs-120,
	) > 1e-12 {
		t.Fatalf(
			"latest RTT mismatch: got %.12f",
			result.RTTLatestMs,
		)
	}

	if math.Abs(
		result.LossDeltaRTCPvsRTPPercent-1.0,
	) > 1e-12 {
		t.Fatalf(
			"loss delta mismatch: got %.12f want 1.0",
			result.LossDeltaRTCPvsRTPPercent,
		)
	}

	if math.Abs(
		result.JitterDeltaRTCPvsRTPMs-5.0,
	) > 1e-12 {
		t.Fatalf(
			"jitter delta mismatch: got %.12f want 5.0",
			result.JitterDeltaRTCPvsRTPMs,
		)
	}
}

func TestExtractStreamFeaturesWithoutRTCP(t *testing.T) {
	key := rtp.StreamKey{
		SSRC:            0x12345678,
		SourceIP:        "192.168.1.10",
		DestinationIP:   "192.168.1.20",
		SourcePort:      4000,
		DestinationPort: 5000,
	}

	metrics := analyzer.UnifiedMediaMetrics{
		CallID:      "call-no-rtcp",
		Key:         key,
		PayloadType: 0,
		ClockRate:   8000,

		RTP: rtp.StreamStats{
			Key:                  key,
			PacketCount:          100,
			UniquePackets:        100,
			ExpectedPackets:      100,
			LostPackets:          0,
			LossPercent:          0,
			JitterAvailable:      true,
			JitterClockRate:      8000,
			JitterTimestampUnits: 32,
			JitterMilliseconds:   4,
		},
	}

	result := ExtractStreamFeatures(metrics)

	if result.HasRTCP != 0 {
		t.Fatal("expected HasRTCP=0")
	}

	if result.RTCPObservationCount != 0 {
		t.Fatalf(
			"expected zero RTCP observations, got %.0f",
			result.RTCPObservationCount,
		)
	}

	if result.RTTAvailableAverage != 0 ||
		result.RTTAvailableLatest != 0 {
		t.Fatal("expected RTT to be unavailable")
	}

	if result.RTCPJitterAvailableAverage != 0 ||
		result.RTCPJitterAvailableLatest != 0 {
		t.Fatal(
			"expected RTCP jitter to be unavailable",
		)
	}

	if result.LossDeltaRTCPvsRTPPercent != 0 {
		t.Fatalf(
			"expected zero loss delta, got %.12f",
			result.LossDeltaRTCPvsRTPPercent,
		)
	}

	if result.JitterDeltaRTCPvsRTPMs != 0 {
		t.Fatalf(
			"expected zero jitter delta, got %.12f",
			result.JitterDeltaRTCPvsRTPMs,
		)
	}
}

func TestExtractAllStreamFeatures(t *testing.T) {
	metrics := []analyzer.UnifiedMediaMetrics{
		{
			CallID: "call-1",
			Key: rtp.StreamKey{
				SSRC: 0x11111111,
			},
		},
		{
			CallID: "call-2",
			Key: rtp.StreamKey{
				SSRC: 0x22222222,
			},
		},
	}

	results := ExtractAllStreamFeatures(metrics)

	if len(results) != 2 {
		t.Fatalf(
			"result count mismatch: got %d want 2",
			len(results),
		)
	}

	if results[0].CallID != "call-1" {
		t.Fatalf(
			"first result call mismatch: got %q",
			results[0].CallID,
		)
	}

	if results[1].CallID != "call-2" {
		t.Fatalf(
			"second result call mismatch: got %q",
			results[1].CallID,
		)
	}
}

func TestBoolFloat(t *testing.T) {
	if boolFloat(false) != 0 {
		t.Fatal("false must convert to 0")
	}

	if boolFloat(true) != 1 {
		t.Fatal("true must convert to 1")
	}
}

func TestAbsoluteDifference(t *testing.T) {
	tests := []struct {
		left  float64
		right float64
		want  float64
	}{
		{
			left:  10,
			right: 4,
			want:  6,
		},
		{
			left:  4,
			right: 10,
			want:  6,
		},
		{
			left:  5,
			right: 5,
			want:  0,
		},
	}

	for _, tt := range tests {
		got := absoluteDifference(
			tt.left,
			tt.right,
		)

		if math.Abs(got-tt.want) > 1e-12 {
			t.Fatalf(
				"absolute difference mismatch: got %.12f want %.12f",
				got,
				tt.want,
			)
		}
	}
}

func TestSchemaVersionIsNonEmpty(t *testing.T) {
	if SchemaVersion == "" {
		t.Fatal("schema version must not be empty")
	}
}
