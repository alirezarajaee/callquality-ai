package features

import (
	"time"

	"github.com/alirezarajaee/callquality-ai/app/internal/analyzer"
)

// SchemaVersion identifies the feature schema used by this project.
const SchemaVersion = "1.0"

// CallFeatures contains call-level numerical features.
type CallFeatures struct {
	SchemaVersion string

	CallID string

	SetupDurationMs float64
	CallDurationMs  float64

	FinalResponseCode float64

	HasInvite  float64
	HasRinging float64
	HasOK      float64
	HasACK     float64
	HasBYE     float64

	MediaStreamCount float64
}

// StreamFeatures contains normalized numerical features for one
// RTP media stream and its correlated RTCP information.
type StreamFeatures struct {
	SchemaVersion string

	CallID string

	SSRC uint32

	PayloadType float64
	ClockRate   float64

	PacketCount       float64
	UniquePackets     float64
	DuplicatePackets  float64
	OutOfOrderPackets float64

	ExpectedPackets float64
	LostPackets     float64
	RTPLossPercent  float64

	RTPJitterAvailable float64
	RTPJitterMs        float64

	HasRTCP              float64
	RTCPObservationCount float64

	RTCPLossAveragePercent float64
	RTCPLossLatestPercent  float64

	RTCPCumulativeLost float64

	RTCPJitterAverageMs float64
	RTCPJitterLatestMs  float64

	RTCPJitterAvailableAverage float64
	RTCPJitterAvailableLatest  float64

	RTTAvailableAverage float64
	RTTAvailableLatest  float64

	RTTAverageMs float64
	RTTLatestMs  float64

	LossDeltaRTCPvsRTPPercent float64
	JitterDeltaRTCPvsRTPMs    float64
}

// ExtractCallFeatures converts a reconstructed call into
// deterministic numerical call-level features.
func ExtractCallFeatures(call analyzer.Call) CallFeatures {
	return CallFeatures{
		SchemaVersion: SchemaVersion,

		CallID: call.CallID,

		SetupDurationMs: durationMilliseconds(
			call.SetupDuration,
		),

		CallDurationMs: durationMilliseconds(
			call.Duration,
		),

		FinalResponseCode: float64(
			call.FinalResponseCode,
		),

		HasInvite:  boolFloat(call.HasInvite),
		HasRinging: boolFloat(call.HasRinging),
		HasOK:      boolFloat(call.HasOK),
		HasACK:     boolFloat(call.HasACK),
		HasBYE:     boolFloat(call.HasBYE),

		MediaStreamCount: float64(
			len(call.RTPStreams),
		),
	}
}

// ExtractStreamFeatures converts unified RTP/RTCP measurements
// into a fixed numerical feature vector.
func ExtractStreamFeatures(
	metrics analyzer.UnifiedMediaMetrics,
) StreamFeatures {
	result := StreamFeatures{
		SchemaVersion: SchemaVersion,

		CallID: metrics.CallID,

		SSRC: metrics.Key.SSRC,

		PayloadType: float64(
			metrics.PayloadType,
		),

		ClockRate: float64(
			metrics.ClockRate,
		),

		PacketCount: float64(
			metrics.RTP.PacketCount,
		),

		UniquePackets: float64(
			metrics.RTP.UniquePackets,
		),

		DuplicatePackets: float64(
			metrics.RTP.DuplicatePackets,
		),

		OutOfOrderPackets: float64(
			metrics.RTP.OutOfOrderPackets,
		),

		ExpectedPackets: float64(
			metrics.RTP.ExpectedPackets,
		),

		LostPackets: float64(
			metrics.RTP.LostPackets,
		),

		RTPLossPercent: metrics.RTP.LossPercent,

		RTPJitterAvailable: boolFloat(
			metrics.RTP.JitterAvailable,
		),

		RTPJitterMs: metrics.RTP.JitterMilliseconds,

		HasRTCP: boolFloat(
			metrics.HasRTCP,
		),

		RTCPObservationCount: float64(
			metrics.RTCPObservationCount,
		),

		RTCPLossAveragePercent: metrics.AverageFractionLostPercent,

		RTCPLossLatestPercent: metrics.LatestFractionLostPercent,

		RTCPCumulativeLost: float64(
			metrics.LatestCumulativeLost,
		),

		RTCPJitterAverageMs: metrics.AverageJitterMilliseconds,

		RTCPJitterLatestMs: metrics.LatestJitterMilliseconds,

		RTCPJitterAvailableAverage: boolFloat(
			metrics.AverageJitterAvailable,
		),

		RTCPJitterAvailableLatest: boolFloat(
			metrics.LatestJitterAvailable,
		),

		RTTAvailableAverage: boolFloat(
			metrics.AveragePassiveRTTAvailable,
		),

		RTTAvailableLatest: boolFloat(
			metrics.LatestPassiveRTTAvailable,
		),

		RTTAverageMs: secondsToMilliseconds(
			metrics.AveragePassiveRTTSeconds,
		),

		RTTLatestMs: secondsToMilliseconds(
			metrics.LatestPassiveRTTSeconds,
		),
	}

	result.LossDeltaRTCPvsRTPPercent =
		absoluteDifference(
			result.RTCPLossAveragePercent,
			result.RTPLossPercent,
		)

	if result.RTPJitterAvailable > 0 &&
		result.RTCPJitterAvailableAverage > 0 {

		result.JitterDeltaRTCPvsRTPMs =
			absoluteDifference(
				result.RTCPJitterAverageMs,
				result.RTPJitterMs,
			)
	}

	return result
}

// ExtractAllStreamFeatures converts all unified media metrics
// into feature vectors while preserving their original order.
func ExtractAllStreamFeatures(
	metrics []analyzer.UnifiedMediaMetrics,
) []StreamFeatures {
	if len(metrics) == 0 {
		return nil
	}

	result := make(
		[]StreamFeatures,
		0,
		len(metrics),
	)

	for _, metric := range metrics {
		result = append(
			result,
			ExtractStreamFeatures(metric),
		)
	}

	return result
}

func durationMilliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}

func secondsToMilliseconds(
	seconds float64,
) float64 {
	return seconds * 1000.0
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}

	return 0
}

func absoluteDifference(
	left float64,
	right float64,
) float64 {
	if left >= right {
		return left - right
	}

	return right - left
}
