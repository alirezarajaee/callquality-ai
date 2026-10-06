package callanalysis

import (
	"math"
	"testing"
	"time"

	"github.com/alirezarajaee/callquality-ai/app/internal/analyzer"
	"github.com/alirezarajaee/callquality-ai/app/internal/diagnosis"
	"github.com/alirezarajaee/callquality-ai/app/internal/quality"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
)

func TestAnalyzeCallAggregatesStreams(t *testing.T) {
	keyOne := rtp.StreamKey{
		SSRC:            0x11111111,
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.2",
		SourcePort:      10000,
		DestinationPort: 20000,
	}

	keyTwo := rtp.StreamKey{
		SSRC:            0x22222222,
		SourceIP:        "10.0.0.2",
		DestinationIP:   "10.0.0.1",
		SourcePort:      20000,
		DestinationPort: 10000,
	}

	start := time.Date(
		2026,
		1,
		1,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	call := analyzer.Call{
		CallID: "call-001",

		StartTime:     start,
		RingingTime:   start.Add(300 * time.Millisecond),
		ConnectedTime: start.Add(700 * time.Millisecond),
		EndTime:       start.Add(10 * time.Second),

		SetupDuration: 700 * time.Millisecond,
		Duration:      9300 * time.Millisecond,

		FinalResponseCode: 200,

		RTPStreams: []analyzer.RTPStreamResult{
			{
				Key:         keyOne,
				PayloadType: 0,
				Stats: makeStreamStats(
					keyOne,
					1000,
					1.0,
					10,
				),
			},
			{
				Key:         keyTwo,
				PayloadType: 0,
				Stats: makeStreamStats(
					keyTwo,
					1000,
					8.0,
					40,
				),
			},
		},
	}

	metrics := []analyzer.UnifiedMediaMetrics{
		{
			CallID:      "call-001",
			Key:         keyOne,
			PayloadType: 0,
			ClockRate:   8000,

			RTP: makeStreamStats(
				keyOne,
				1000,
				1.0,
				10,
			),

			HasRTCP:                    true,
			RTCPObservationCount:       2,
			AverageFractionLostPercent: 1.2,
			LatestFractionLostPercent:  1.3,
			LatestCumulativeLost:       12,
			AverageJitterMilliseconds:  12,
			LatestJitterMilliseconds:   13,
			AverageJitterAvailable:     true,
			LatestJitterAvailable:      true,
			AveragePassiveRTTSeconds:   0.04,
			LatestPassiveRTTSeconds:    0.05,
			AveragePassiveRTTAvailable: true,
			LatestPassiveRTTAvailable:  true,
		},
		{
			CallID:      "call-001",
			Key:         keyTwo,
			PayloadType: 0,
			ClockRate:   8000,

			RTP: makeStreamStats(
				keyTwo,
				1000,
				8.0,
				40,
			),

			HasRTCP:                    true,
			RTCPObservationCount:       2,
			AverageFractionLostPercent: 8.0,
			LatestFractionLostPercent:  9.0,
			LatestCumulativeLost:       90,
			AverageJitterMilliseconds:  45,
			LatestJitterMilliseconds:   48,
			AverageJitterAvailable:     true,
			LatestJitterAvailable:      true,
			AveragePassiveRTTSeconds:   0.20,
			LatestPassiveRTTSeconds:    0.22,
			AveragePassiveRTTAvailable: true,
			LatestPassiveRTTAvailable:  true,
		},
	}

	result := AnalyzeCall(
		call,
		metrics,
	)

	if result.EngineVersion != EngineVersion {
		t.Fatalf(
			"engine version mismatch: got %q want %q",
			result.EngineVersion,
			EngineVersion,
		)
	}

	if result.CallID != "call-001" {
		t.Fatalf(
			"call ID mismatch: got %q",
			result.CallID,
		)
	}

	if !result.StartTime.Equal(start) {
		t.Fatal("start time mismatch")
	}

	if !result.RingingTime.Equal(
		start.Add(300 * time.Millisecond),
	) {
		t.Fatal("ringing time mismatch")
	}

	if result.SetupDurationMs != 700 {
		t.Fatalf(
			"setup duration mismatch: got %.6f",
			result.SetupDurationMs,
		)
	}

	if math.Abs(
		result.CallDurationMs-9300,
	) > 1e-12 {
		t.Fatalf(
			"call duration mismatch: got %.6f",
			result.CallDurationMs,
		)
	}

	if result.FinalResponseCode != 200 {
		t.Fatalf(
			"response code mismatch: got %d",
			result.FinalResponseCode,
		)
	}

	if result.StreamCount != 2 {
		t.Fatalf(
			"stream count mismatch: got %d want 2",
			result.StreamCount,
		)
	}

	if result.AnalyzedStreamCount != 2 {
		t.Fatalf(
			"analyzed stream count mismatch: got %d want 2",
			result.AnalyzedStreamCount,
		)
	}

	if len(result.Streams) != 2 {
		t.Fatalf(
			"stream analysis count mismatch: got %d want 2",
			len(result.Streams),
		)
	}

	if result.OverallScore > result.AverageScore {
		t.Fatalf(
			"conservative overall score %.6f cannot exceed average %.6f",
			result.OverallScore,
			result.AverageScore,
		)
	}

	if result.Streams[0].Features.CallID != "call-001" {
		t.Fatal("first stream feature call ID mismatch")
	}

	if result.Streams[1].Features.CallID != "call-001" {
		t.Fatal("second stream feature call ID mismatch")
	}

	if !result.Streams[0].EModelAvailable {
		t.Fatal("expected first stream E-model result")
	}

	if !result.Streams[1].EModelAvailable {
		t.Fatal("expected second stream E-model result")
	}

	if !result.EModelAvailable {
		t.Fatal("expected call-level E-model availability")
	}

	if result.AverageMOS <= 1 ||
		result.AverageMOS > 4.5 {
		t.Fatalf(
			"unexpected average MOS %.6f",
			result.AverageMOS,
		)
	}

	if result.AverageRFactor <= 0 ||
		result.AverageRFactor > 100 {
		t.Fatalf(
			"unexpected average R-factor %.6f",
			result.AverageRFactor,
		)
	}

	if result.PrimaryFinding == "" {
		t.Fatal("expected a primary call-level finding")
	}

	if result.PrimaryFindingSSRC == 0 {
		t.Fatal("expected a primary finding SSRC")
	}
}

func TestAnalyzeCallUsesFallbackWhenMetricsAreMissing(t *testing.T) {
	key := rtp.StreamKey{
		SSRC:            0x33333333,
		SourceIP:        "192.168.0.1",
		DestinationIP:   "192.168.0.2",
		SourcePort:      4000,
		DestinationPort: 5000,
	}

	call := analyzer.Call{
		CallID: "call-fallback",
		RTPStreams: []analyzer.RTPStreamResult{
			{
				Key:         key,
				PayloadType: 0,
				Stats: makeStreamStats(
					key,
					100,
					2,
					5,
				),
			},
		},
	}

	result := AnalyzeCall(
		call,
		nil,
	)

	if result.StreamCount != 1 {
		t.Fatalf(
			"stream count mismatch: got %d",
			result.StreamCount,
		)
	}

	if result.AnalyzedStreamCount != 1 {
		t.Fatalf(
			"expected one analyzed stream, got %d",
			result.AnalyzedStreamCount,
		)
	}

	if len(result.Streams) != 1 {
		t.Fatalf(
			"expected one stream analysis, got %d",
			len(result.Streams),
		)
	}

	if result.Streams[0].Metrics.HasRTCP {
		t.Fatal(
			"fallback metrics must not claim RTCP availability",
		)
	}

	if result.Streams[0].Features.RTPLossPercent != 2 {
		t.Fatalf(
			"fallback RTP loss mismatch: got %.6f",
			result.Streams[0].Features.RTPLossPercent,
		)
	}
}

func TestAnalyzeCallWithNoRTPStreams(t *testing.T) {
	call := analyzer.Call{
		CallID:        "empty-call",
		SetupDuration: 500 * time.Millisecond,
		Duration:      0,
	}

	result := AnalyzeCall(
		call,
		nil,
	)

	if result.StreamCount != 0 {
		t.Fatalf(
			"expected zero streams, got %d",
			result.StreamCount,
		)
	}

	if result.AnalyzedStreamCount != 0 {
		t.Fatalf(
			"expected zero analyzed streams, got %d",
			result.AnalyzedStreamCount,
		)
	}

	if result.OverallLevel != quality.LevelUnknown {
		t.Fatalf(
			"expected unknown overall level, got %q",
			result.OverallLevel,
		)
	}

	if result.EModelAvailable {
		t.Fatal(
			"did not expect E-model without media streams",
		)
	}

	if result.PrimaryFinding != "" {
		t.Fatalf(
			"expected no primary finding, got %q",
			result.PrimaryFinding,
		)
	}
}

func TestAnalyzeCallsPreservesOrder(t *testing.T) {
	firstKey := rtp.StreamKey{
		SSRC:            0x11110000,
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.2",
		SourcePort:      1000,
		DestinationPort: 2000,
	}

	secondKey := rtp.StreamKey{
		SSRC:            0x22220000,
		SourceIP:        "10.0.0.3",
		DestinationIP:   "10.0.0.4",
		SourcePort:      3000,
		DestinationPort: 4000,
	}

	calls := []analyzer.Call{
		{
			CallID: "call-1",
			RTPStreams: []analyzer.RTPStreamResult{
				{
					Key:         firstKey,
					PayloadType: 0,
					Stats: makeStreamStats(
						firstKey,
						100,
						0.5,
						2,
					),
				},
			},
		},
		{
			CallID: "call-2",
			RTPStreams: []analyzer.RTPStreamResult{
				{
					Key:         secondKey,
					PayloadType: 0,
					Stats: makeStreamStats(
						secondKey,
						100,
						0.5,
						2,
					),
				},
			},
		},
	}

	results := AnalyzeCalls(
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
}

func TestAnalyzeCallDoesNotUseMetricsFromAnotherCall(t *testing.T) {
	key := rtp.StreamKey{
		SSRC:            0x44444444,
		SourceIP:        "10.1.1.1",
		DestinationIP:   "10.1.1.2",
		SourcePort:      6000,
		DestinationPort: 7000,
	}

	call := analyzer.Call{
		CallID: "call-real",
		RTPStreams: []analyzer.RTPStreamResult{
			{
				Key:         key,
				PayloadType: 0,
				Stats: makeStreamStats(
					key,
					100,
					3,
					10,
				),
			},
		},
	}

	wrongMetrics := []analyzer.UnifiedMediaMetrics{
		{
			CallID: "call-other",
			Key:    key,
			RTP: makeStreamStats(
				key,
				100,
				20,
				80,
			),
			HasRTCP:                    true,
			AverageFractionLostPercent: 30,
		},
	}

	result := AnalyzeCall(
		call,
		wrongMetrics,
	)

	if len(result.Streams) != 1 {
		t.Fatalf(
			"expected one stream, got %d",
			len(result.Streams),
		)
	}

	if result.Streams[0].Metrics.HasRTCP {
		t.Fatal(
			"metrics belonging to another call must not be attached",
		)
	}

	if result.Streams[0].Features.RTPLossPercent != 3 {
		t.Fatalf(
			"expected fallback RTP loss 3, got %.6f",
			result.Streams[0].Features.RTPLossPercent,
		)
	}
}

func TestFindingSeverityRank(t *testing.T) {
	if findingSeverityRank(
		diagnosis.SeverityCritical,
	) <= findingSeverityRank(
		diagnosis.SeverityWarning,
	) {
		t.Fatal("critical must rank above warning")
	}

	if findingSeverityRank(
		diagnosis.SeverityWarning,
	) <= findingSeverityRank(
		diagnosis.SeverityInfo,
	) {
		t.Fatal("warning must rank above info")
	}
}

func makeStreamStats(
	key rtp.StreamKey,
	packetCount int,
	lossPercent float64,
	jitterMs float64,
) rtp.StreamStats {
	lostPackets := int64(
		float64(packetCount) *
			lossPercent /
			100.0,
	)

	return rtp.StreamStats{
		Key:                  key,
		PacketCount:          packetCount,
		UniquePackets:        packetCount,
		ExpectedPackets:      int64(packetCount),
		LostPackets:          lostPackets,
		LossPercent:          lossPercent,
		JitterAvailable:      true,
		JitterClockRate:      8000,
		JitterTimestampUnits: jitterMs * 8,
		JitterMilliseconds:   jitterMs,
	}
}
