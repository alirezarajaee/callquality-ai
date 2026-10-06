package quality

import (
	"math"
	"testing"

	"github.com/alirezarajaee/callquality-ai/app/internal/features"
)

func TestAssessStreamGoodQuality(t *testing.T) {
	input := features.StreamFeatures{
		SchemaVersion: "1.0",
		CallID:        "call-001",
		SSRC:          0x11223344,

		PacketCount:       1000,
		DuplicatePackets:  2,
		OutOfOrderPackets: 5,

		RTPLossPercent: 2.0,

		RTPJitterAvailable: 1,
		RTPJitterMs:        15,

		HasRTCP: 1,

		RTCPLossAveragePercent: 1.5,

		RTCPJitterAvailableAverage: 1,
		RTCPJitterAverageMs:        12,

		RTTAvailableAverage: 1,
		RTTAverageMs:        80,
	}

	result := AssessStream(input)

	if !result.Available {
		t.Fatal("expected assessment to be available")
	}

	if result.Level != LevelGood {
		t.Fatalf(
			"quality level mismatch: got %q want %q",
			result.Level,
			LevelGood,
		)
	}

	if math.Abs(
		result.Effective.LossPercent-2,
	) > 1e-12 {
		t.Fatalf(
			"effective loss mismatch: got %.12f",
			result.Effective.LossPercent,
		)
	}

	if result.Effective.LossSource != "rtp" {
		t.Fatalf(
			"loss source mismatch: got %q want %q",
			result.Effective.LossSource,
			"rtp",
		)
	}

	if math.Abs(
		result.Effective.JitterMs-15,
	) > 1e-12 {
		t.Fatalf(
			"effective jitter mismatch: got %.12f",
			result.Effective.JitterMs,
		)
	}

	if result.Effective.JitterSource != "rtp" {
		t.Fatalf(
			"jitter source mismatch: got %q want %q",
			result.Effective.JitterSource,
			"rtp",
		)
	}

	if math.Abs(
		result.Effective.RTTMs-80,
	) > 1e-12 {
		t.Fatalf(
			"effective RTT mismatch: got %.12f",
			result.Effective.RTTMs,
		)
	}

	if result.Effective.RTTSource != "rtcp_passive_average" {
		t.Fatalf(
			"RTT source mismatch: got %q",
			result.Effective.RTTSource,
		)
	}

	if result.PrimaryFactor != FactorPacketLoss {
		t.Fatalf(
			"primary factor mismatch: got %q want %q",
			result.PrimaryFactor,
			FactorPacketLoss,
		)
	}

	if result.Score <= 75 || result.Score >= 90 {
		t.Fatalf(
			"unexpected score %.6f for good-quality test",
			result.Score,
		)
	}
}

func TestAssessStreamExcellentQuality(t *testing.T) {
	input := features.StreamFeatures{
		CallID:      "excellent-call",
		SSRC:        0x10000001,
		PacketCount: 1000,

		RTPLossPercent: 0.1,

		RTPJitterAvailable: 1,
		RTPJitterMs:        2,

		RTTAvailableAverage: 1,
		RTTAverageMs:        20,
	}

	result := AssessStream(input)

	if !result.Available {
		t.Fatal("expected assessment to be available")
	}

	if result.Level != LevelExcellent {
		t.Fatalf(
			"quality level mismatch: got %q want %q",
			result.Level,
			LevelExcellent,
		)
	}

	if result.Score < 90 {
		t.Fatalf(
			"expected excellent score >= 90, got %.6f",
			result.Score,
		)
	}
}

func TestAssessStreamPoorQuality(t *testing.T) {
	input := features.StreamFeatures{
		CallID: "poor-call",
		SSRC:   0x20000002,

		PacketCount:       1000,
		DuplicatePackets:  10,
		OutOfOrderPackets: 50,

		RTPLossPercent: 9,

		RTPJitterAvailable: 1,
		RTPJitterMs:        45,

		RTTAvailableAverage: 1,
		RTTAverageMs:        250,
	}

	result := AssessStream(input)

	if !result.Available {
		t.Fatal("expected assessment to be available")
	}

	if result.Level != LevelPoor &&
		result.Level != LevelCritical {
		t.Fatalf(
			"expected poor or critical quality, got %q",
			result.Level,
		)
	}

	if result.Score >= 60 {
		t.Fatalf(
			"expected score below 60, got %.6f",
			result.Score,
		)
	}

	if result.PrimaryFactor == "" {
		t.Fatal("expected a primary quality factor")
	}
}

func TestAssessStreamCriticalQuality(t *testing.T) {
	input := features.StreamFeatures{
		CallID:      "critical-call",
		SSRC:        0x30000003,
		PacketCount: 1000,

		DuplicatePackets:  50,
		OutOfOrderPackets: 100,

		RTPLossPercent: 25,

		RTPJitterAvailable: 1,
		RTPJitterMs:        100,

		RTTAvailableAverage: 1,
		RTTAverageMs:        1000,
	}

	result := AssessStream(input)

	if !result.Available {
		t.Fatal("expected assessment to be available")
	}

	if result.Level != LevelCritical {
		t.Fatalf(
			"quality level mismatch: got %q want %q",
			result.Level,
			LevelCritical,
		)
	}

	if math.Abs(result.Score) > 1e-12 {
		t.Fatalf(
			"expected score to clamp at zero, got %.12f",
			result.Score,
		)
	}
}

func TestAssessStreamWithoutOptionalMetrics(t *testing.T) {
	input := features.StreamFeatures{
		CallID:              "partial-call",
		SSRC:                0x40000004,
		PacketCount:         100,
		RTPLossPercent:      1,
		RTPJitterAvailable:  0,
		HasRTCP:             0,
		RTTAvailableAverage: 0,
		RTTAvailableLatest:  0,
	}

	result := AssessStream(input)

	if !result.Available {
		t.Fatal("expected assessment to be available")
	}

	if result.Effective.JitterSource != "" {
		t.Fatalf(
			"expected jitter source to be empty, got %q",
			result.Effective.JitterSource,
		)
	}

	if result.Effective.RTTSource != "" {
		t.Fatalf(
			"expected RTT source to be empty, got %q",
			result.Effective.RTTSource,
		)
	}

	if result.Level == LevelUnknown {
		t.Fatal("quality level should be known with RTP packet data")
	}
}

func TestAssessStreamUsesRTCPWhenItIsWorse(t *testing.T) {
	input := features.StreamFeatures{
		CallID:                 "rtcp-degraded-call",
		SSRC:                   0x50000005,
		PacketCount:            100,
		RTPLossPercent:         1,
		HasRTCP:                1,
		RTCPLossAveragePercent: 6,

		RTPJitterAvailable:         1,
		RTPJitterMs:                5,
		RTCPJitterAvailableAverage: 1,
		RTCPJitterAverageMs:        25,
	}

	result := AssessStream(input)

	if math.Abs(
		result.Effective.LossPercent-6,
	) > 1e-12 {
		t.Fatalf(
			"expected RTCP loss to be selected, got %.12f",
			result.Effective.LossPercent,
		)
	}

	if result.Effective.LossSource != "rtcp_average" {
		t.Fatalf(
			"expected RTCP loss source, got %q",
			result.Effective.LossSource,
		)
	}

	if math.Abs(
		result.Effective.JitterMs-25,
	) > 1e-12 {
		t.Fatalf(
			"expected RTCP jitter to be selected, got %.12f",
			result.Effective.JitterMs,
		)
	}

	if result.Effective.JitterSource != "rtcp_average" {
		t.Fatalf(
			"expected RTCP jitter source, got %q",
			result.Effective.JitterSource,
		)
	}
}

func TestAssessStreamNoPackets(t *testing.T) {
	input := features.StreamFeatures{
		CallID:      "empty-call",
		SSRC:        0x60000006,
		PacketCount: 0,
	}

	result := AssessStream(input)

	if result.Available {
		t.Fatal("expected assessment to be unavailable")
	}

	if result.Level != LevelUnknown {
		t.Fatalf(
			"quality level mismatch: got %q want %q",
			result.Level,
			LevelUnknown,
		)
	}

	if result.Score != 0 {
		t.Fatalf(
			"expected zero score for unavailable assessment, got %.12f",
			result.Score,
		)
	}

	if result.Reason != "no RTP packets available" {
		t.Fatalf(
			"unexpected reason: %q",
			result.Reason,
		)
	}
}

func TestAssessStreamsPreservesOrder(t *testing.T) {
	inputs := []features.StreamFeatures{
		{
			CallID:         "call-1",
			SSRC:           0x11111111,
			PacketCount:    100,
			RTPLossPercent: 0,
		},
		{
			CallID:         "call-2",
			SSRC:           0x22222222,
			PacketCount:    100,
			RTPLossPercent: 20,
		},
	}

	results := AssessStreams(inputs)

	if len(results) != 2 {
		t.Fatalf(
			"result count mismatch: got %d want 2",
			len(results),
		)
	}

	if results[0].CallID != "call-1" {
		t.Fatalf(
			"first result mismatch: got %q",
			results[0].CallID,
		)
	}

	if results[1].CallID != "call-2" {
		t.Fatalf(
			"second result mismatch: got %q",
			results[1].CallID,
		)
	}
}

func TestLevelFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  QualityLevel
	}{
		{100, LevelExcellent},
		{90, LevelExcellent},
		{89.99, LevelGood},
		{75, LevelGood},
		{74.99, LevelFair},
		{60, LevelFair},
		{59.99, LevelPoor},
		{40, LevelPoor},
		{39.99, LevelCritical},
		{0, LevelCritical},
	}

	for _, tt := range tests {
		got := levelFromScore(tt.score)

		if got != tt.want {
			t.Fatalf(
				"score %.2f: got %q want %q",
				tt.score,
				got,
				tt.want,
			)
		}
	}
}

func TestLinearPenalty(t *testing.T) {
	tests := []struct {
		value    float64
		limit    float64
		max      float64
		expected float64
	}{
		{
			value:    0,
			limit:    10,
			max:      45,
			expected: 0,
		},
		{
			value:    5,
			limit:    10,
			max:      45,
			expected: 22.5,
		},
		{
			value:    10,
			limit:    10,
			max:      45,
			expected: 45,
		},
		{
			value:    20,
			limit:    10,
			max:      45,
			expected: 45,
		},
	}

	for _, tt := range tests {
		got := linearPenalty(
			tt.value,
			tt.limit,
			tt.max,
		)

		if math.Abs(got-tt.expected) > 1e-12 {
			t.Fatalf(
				"value %.2f: got %.12f want %.12f",
				tt.value,
				got,
				tt.expected,
			)
		}
	}
}

func TestRatePercent(t *testing.T) {
	tests := []struct {
		count float64
		total float64
		want  float64
	}{
		{0, 100, 0},
		{5, 100, 5},
		{10, 200, 5},
		{10, 0, 0},
		{0, 0, 0},
	}

	for _, tt := range tests {
		got := ratePercent(
			tt.count,
			tt.total,
		)

		if math.Abs(got-tt.want) > 1e-12 {
			t.Fatalf(
				"count %.2f total %.2f: got %.12f want %.12f",
				tt.count,
				tt.total,
				got,
				tt.want,
			)
		}
	}
}
