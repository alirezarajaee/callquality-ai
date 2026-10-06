package quality

import (
	"github.com/alirezarajaee/callquality-ai/app/internal/features"
)

// EngineVersion identifies the deterministic engineering quality model.
const EngineVersion = "1.0"

// QualityLevel is the human-readable quality band produced by the
// engineering quality model.
//
// This is not MOS and is not an ITU-T E-model output.
type QualityLevel string

const (
	LevelExcellent QualityLevel = "excellent"
	LevelGood      QualityLevel = "good"
	LevelFair      QualityLevel = "fair"
	LevelPoor      QualityLevel = "poor"
	LevelCritical  QualityLevel = "critical"
	LevelUnknown   QualityLevel = "unknown"
)

// FactorName identifies an individual quality factor.
type FactorName string

const (
	FactorPacketLoss FactorName = "packet_loss"
	FactorJitter     FactorName = "jitter"
	FactorRTT        FactorName = "round_trip_time"
	FactorReordering FactorName = "reordering"
	FactorDuplicates FactorName = "duplicates"
)

// QualityFactor explains one contribution to the final quality score.
type QualityFactor struct {
	Name FactorName

	Value float64
	Unit  string

	Penalty float64

	Available bool
}

// EffectiveMetrics contains the values actually used by the quality
// engine after combining the available RTP and RTCP measurements.
type EffectiveMetrics struct {
	LossPercent float64
	LossSource  string

	JitterMs     float64
	JitterSource string

	RTTMs     float64
	RTTSource string

	OutOfOrderPercent float64
	DuplicatePercent  float64
}

// StreamAssessment is the quality result for one media stream.
type StreamAssessment struct {
	EngineVersion string

	CallID string
	SSRC   uint32

	Available bool
	Reason    string

	Score float64
	Level QualityLevel

	Effective EffectiveMetrics

	Factors []QualityFactor

	PrimaryFactor FactorName
}

// AssessStream evaluates one stream feature vector using a deterministic
// engineering heuristic.
//
// Maximum penalties:
//
//   packet loss: 45 points
//   jitter:      25 points
//   RTT:         20 points
//   reordering:  7 points
//   duplicates:  3 points
//
// Total possible penalty: 100 points.
//
// The result is intentionally explainable. It is not MOS, not an
// E-model rating, and not a claim of user-perceived speech quality.
func AssessStream(
	input features.StreamFeatures,
) StreamAssessment {
	result := StreamAssessment{
		EngineVersion: EngineVersion,
		CallID:        input.CallID,
		SSRC:          input.SSRC,
		Factors:       make([]QualityFactor, 0, 5),
	}

	if input.PacketCount <= 0 {
		result.Available = false
		result.Reason = "no RTP packets available"
		result.Level = LevelUnknown
		return result
	}

	result.Available = true

	effective := deriveEffectiveMetrics(input)
	result.Effective = effective

	factors := []QualityFactor{
		buildLossFactor(effective),
		buildJitterFactor(effective),
		buildRTTFactor(effective),
		buildReorderingFactor(effective),
		buildDuplicateFactor(effective),
	}

	result.Factors = factors
	result.Score = scoreFromFactors(factors)
	result.Level = levelFromScore(result.Score)
	result.PrimaryFactor = primaryFactor(factors)

	return result
}

// AssessStreams evaluates multiple streams while preserving input order.
func AssessStreams(
	inputs []features.StreamFeatures,
) []StreamAssessment {
	if len(inputs) == 0 {
		return nil
	}

	results := make(
		[]StreamAssessment,
		0,
		len(inputs),
	)

	for _, input := range inputs {
		results = append(
			results,
			AssessStream(input),
		)
	}

	return results
}

func deriveEffectiveMetrics(
	input features.StreamFeatures,
) EffectiveMetrics {
	effective := EffectiveMetrics{
		LossPercent: clampNonNegative(
			input.RTPLossPercent,
		),
		LossSource: "rtp",
		OutOfOrderPercent: ratePercent(
			input.OutOfOrderPackets,
			input.PacketCount,
		),
		DuplicatePercent: ratePercent(
			input.DuplicatePackets,
			input.PacketCount,
		),
	}

	if input.HasRTCP > 0 {
		rtcpLoss := clampNonNegative(
			input.RTCPLossAveragePercent,
		)

		if rtcpLoss > effective.LossPercent {
			effective.LossPercent = rtcpLoss
			effective.LossSource = "rtcp_average"
		}
	}

	if input.RTPJitterAvailable > 0 {
		effective.JitterMs =
			clampNonNegative(input.RTPJitterMs)

		effective.JitterSource = "rtp"
	}

	if input.RTCPJitterAvailableAverage > 0 {
		rtcpJitter :=
			clampNonNegative(input.RTCPJitterAverageMs)

		if rtcpJitter > effective.JitterMs {
			effective.JitterMs = rtcpJitter
			effective.JitterSource = "rtcp_average"
		}
	}

	if input.RTTAvailableAverage > 0 {
		effective.RTTMs =
			clampNonNegative(input.RTTAverageMs)

		effective.RTTSource = "rtcp_passive_average"
	} else if input.RTTAvailableLatest > 0 {
		effective.RTTMs =
			clampNonNegative(input.RTTLatestMs)

		effective.RTTSource = "rtcp_passive_latest"
	}

	return effective
}

func buildLossFactor(
	effective EffectiveMetrics,
) QualityFactor {
	value := effective.LossPercent

	return QualityFactor{
		Name:      FactorPacketLoss,
		Value:     value,
		Unit:      "percent",
		Penalty:   linearPenalty(value, 10, 45),
		Available: true,
	}
}

func buildJitterFactor(
	effective EffectiveMetrics,
) QualityFactor {
	if effective.JitterSource == "" {
		return QualityFactor{
			Name:      FactorJitter,
			Value:     0,
			Unit:      "ms",
			Penalty:   0,
			Available: false,
		}
	}

	return QualityFactor{
		Name:      FactorJitter,
		Value:     effective.JitterMs,
		Unit:      "ms",
		Penalty:   linearPenalty(effective.JitterMs, 50, 25),
		Available: true,
	}
}

func buildRTTFactor(
	effective EffectiveMetrics,
) QualityFactor {
	if effective.RTTSource == "" {
		return QualityFactor{
			Name:      FactorRTT,
			Value:     0,
			Unit:      "ms",
			Penalty:   0,
			Available: false,
		}
	}

	return QualityFactor{
		Name:      FactorRTT,
		Value:     effective.RTTMs,
		Unit:      "ms",
		Penalty:   linearPenalty(effective.RTTMs, 300, 20),
		Available: true,
	}
}

func buildReorderingFactor(
	effective EffectiveMetrics,
) QualityFactor {
	return QualityFactor{
		Name:  FactorReordering,
		Value: effective.OutOfOrderPercent,
		Unit:  "percent",
		Penalty: linearPenalty(
			effective.OutOfOrderPercent,
			5,
			7,
		),
		Available: true,
	}
}

func buildDuplicateFactor(
	effective EffectiveMetrics,
) QualityFactor {
	return QualityFactor{
		Name:  FactorDuplicates,
		Value: effective.DuplicatePercent,
		Unit:  "percent",
		Penalty: linearPenalty(
			effective.DuplicatePercent,
			5,
			3,
		),
		Available: true,
	}
}

func scoreFromFactors(
	factors []QualityFactor,
) float64 {
	totalPenalty := 0.0

	for _, factor := range factors {
		if !factor.Available {
			continue
		}

		totalPenalty += factor.Penalty
	}

	score := 100.0 - totalPenalty

	if score < 0 {
		return 0
	}

	if score > 100 {
		return 100
	}

	return score
}

func levelFromScore(score float64) QualityLevel {
	switch {
	case score >= 90:
		return LevelExcellent

	case score >= 75:
		return LevelGood

	case score >= 60:
		return LevelFair

	case score >= 40:
		return LevelPoor

	default:
		return LevelCritical
	}
}

func primaryFactor(
	factors []QualityFactor,
) FactorName {
	var (
		bestName    FactorName
		bestPenalty float64
		found       bool
	)

	for _, factor := range factors {
		if !factor.Available || factor.Penalty <= 0 {
			continue
		}

		if !found || factor.Penalty > bestPenalty {
			found = true
			bestPenalty = factor.Penalty
			bestName = factor.Name
		}
	}

	return bestName
}

func linearPenalty(
	value float64,
	fullPenaltyAt float64,
	maxPenalty float64,
) float64 {
	value = clampNonNegative(value)

	if fullPenaltyAt <= 0 || maxPenalty <= 0 {
		return 0
	}

	if value >= fullPenaltyAt {
		return maxPenalty
	}

	return (value / fullPenaltyAt) * maxPenalty
}

func ratePercent(
	count float64,
	total float64,
) float64 {
	if count <= 0 || total <= 0 {
		return 0
	}

	return (count / total) * 100.0
}

func clampNonNegative(value float64) float64 {
	if value < 0 {
		return 0
	}

	return value
}
