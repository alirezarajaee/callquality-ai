package analyzer

import (
	"time"

	"github.com/alirezarajaee/callquality-ai/app/internal/rtcp"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
)

// UnifiedMediaMetrics combines RTP and RTCP measurements for one
// media stream belonging to one reconstructed call.
type UnifiedMediaMetrics struct {
	CallID string

	Key         rtp.StreamKey
	PayloadType uint8

	// RTP contains the packet-level measurements calculated from RTP.
	RTP rtp.StreamStats

	// Clock rate used by RTP jitter calculation.
	// A zero value means the media clock rate is not known.
	ClockRate uint32

	// RTCP availability and observation count.
	HasRTCP              bool
	RTCPObservationCount int

	// Latest RTCP values.
	LatestRTCPCapturedAt time.Time

	LatestFractionLostPercent float64
	LatestCumulativeLost      int32

	LatestJitterTimestampUnits uint32
	LatestJitterMilliseconds   float64
	LatestJitterAvailable      bool

	LatestPassiveRTTSeconds   float64
	LatestPassiveRTTAvailable bool

	// Aggregated RTCP values across all available observations.
	AverageFractionLostPercent float64

	AverageJitterMilliseconds float64
	AverageJitterAvailable    bool

	AveragePassiveRTTSeconds   float64
	AveragePassiveRTTAvailable bool
}

// BuildUnifiedMediaMetrics combines all RTP streams from reconstructed
// calls with their matching RTCP correlation results.
//
// Calls without RTCP still produce a UnifiedMediaMetrics entry.
// This is important because RTCP is optional in some captures.
func BuildUnifiedMediaMetrics(
	calls []Call,
	rtcpResults []RTCPStreamResult,
) []UnifiedMediaMetrics {
	if len(calls) == 0 {
		return nil
	}

	rtcpByKey := make(
		map[unifiedMetricsKey]RTCPStreamResult,
		len(rtcpResults),
	)

	for _, result := range rtcpResults {
		key := unifiedMetricsKey{
			callID: result.CallID,
			stream: result.Key,
		}

		rtcpByKey[key] = result
	}

	results := make(
		[]UnifiedMediaMetrics,
		0,
		countRTPStreams(calls),
	)

	for _, call := range calls {
		for _, stream := range call.RTPStreams {
			result := UnifiedMediaMetrics{
				CallID:      call.CallID,
				Key:         stream.Key,
				PayloadType: stream.PayloadType,
				RTP:         stream.Stats,
				ClockRate:   stream.Stats.JitterClockRate,
			}

			key := unifiedMetricsKey{
				callID: call.CallID,
				stream: stream.Key,
			}

			if rtcpResult, ok := rtcpByKey[key]; ok {
				applyRTCPMetrics(
					&result,
					rtcpResult.ReportObservations,
				)
			}

			results = append(results, result)
		}
	}

	return results
}

type unifiedMetricsKey struct {
	callID string
	stream rtp.StreamKey
}

func countRTPStreams(calls []Call) int {
	count := 0

	for _, call := range calls {
		count += len(call.RTPStreams)
	}

	return count
}

func applyRTCPMetrics(
	result *UnifiedMediaMetrics,
	observations []rtcp.ReportObservation,
) {
	if result == nil || len(observations) == 0 {
		return
	}

	result.HasRTCP = true
	result.RTCPObservationCount = len(observations)

	var (
		fractionLostSum   float64
		fractionLostCount int

		jitterSum   float64
		jitterCount int

		rttSum   float64
		rttCount int

		latest *rtcp.ReportObservation
	)

	for i := range observations {
		observation := observations[i]

		fractionLostSum +=
			observation.Metrics.FractionLostPercent

		fractionLostCount++

		// RTCP jitter is reported in RTP timestamp units. The RTCP
		// correlator may not know the codec clock rate at packet
		// parsing time, so enrich the observation here using the
		// clock rate already resolved from the RTP/SDP analysis.
		if !observation.Metrics.JitterAvailable &&
			result.ClockRate > 0 {
			observation.Metrics.JitterMilliseconds =
				rtcp.JitterMilliseconds(
					observation.Metrics.JitterTimestampUnits,
					result.ClockRate,
				)
			observation.Metrics.JitterAvailable = true
		}

		if observation.Metrics.JitterAvailable {
			jitterSum +=
				observation.Metrics.JitterMilliseconds

			jitterCount++
		}

		if observation.PassiveRTTAvailable {
			rttSum += observation.PassiveRTTSeconds
			rttCount++
		}

		if latest == nil ||
			observation.CapturedAt.After(
				latest.CapturedAt,
			) {

			copy := observation
			latest = &copy
		}
	}

	if fractionLostCount > 0 {
		result.AverageFractionLostPercent =
			fractionLostSum / float64(fractionLostCount)
	}

	if jitterCount > 0 {
		result.AverageJitterMilliseconds =
			jitterSum / float64(jitterCount)

		result.AverageJitterAvailable = true
	}

	if rttCount > 0 {
		result.AveragePassiveRTTSeconds =
			rttSum / float64(rttCount)

		result.AveragePassiveRTTAvailable = true
	}

	if latest != nil {
		result.LatestRTCPCapturedAt =
			latest.CapturedAt

		result.LatestFractionLostPercent =
			latest.Metrics.FractionLostPercent

		result.LatestCumulativeLost =
			latest.Metrics.CumulativePacketsLost

		result.LatestJitterTimestampUnits =
			uint32(latest.Metrics.JitterTimestampUnits)

		result.LatestJitterMilliseconds =
			latest.Metrics.JitterMilliseconds

		result.LatestJitterAvailable =
			latest.Metrics.JitterAvailable

		result.LatestPassiveRTTSeconds =
			latest.PassiveRTTSeconds

		result.LatestPassiveRTTAvailable =
			latest.PassiveRTTAvailable
	}
}
