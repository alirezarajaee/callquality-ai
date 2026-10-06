package callanalysis

import (
	"math"
	"time"

	"github.com/alirezarajaee/callquality-ai/app/internal/analyzer"
	"github.com/alirezarajaee/callquality-ai/app/internal/diagnosis"
	"github.com/alirezarajaee/callquality-ai/app/internal/emodel"
	"github.com/alirezarajaee/callquality-ai/app/internal/features"
	"github.com/alirezarajaee/callquality-ai/app/internal/quality"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
)

// EngineVersion identifies the call-level analysis pipeline.
const EngineVersion = "1.0"

// StreamAnalysis contains the complete analysis chain for one media stream.
type StreamAnalysis struct {
	Key         rtp.StreamKey
	PayloadType uint8

	Metrics  analyzer.UnifiedMediaMetrics
	Features features.StreamFeatures

	Quality quality.StreamAssessment

	EModelAvailable bool
	EModel          emodel.Result

	Diagnosis diagnosis.Result
}

// CallAnalysis contains the aggregated analysis for one reconstructed call.
type CallAnalysis struct {
	EngineVersion string

	CallID string
	State  analyzer.CallState

	StartTime     time.Time
	RingingTime   time.Time
	ConnectedTime time.Time
	EndTime       time.Time

	SetupDurationMs float64
	CallDurationMs  float64

	FinalResponseCode int

	StreamCount         int
	AnalyzedStreamCount int

	// AverageScore is the arithmetic mean of available stream quality
	// scores. It is useful as a summary statistic but does not hide
	// degraded individual streams.
	AverageScore float64

	// OverallScore is the minimum available stream score.
	//
	// This conservative aggregation prevents one badly degraded media
	// direction from being masked by a healthy direction.
	OverallScore float64

	OverallLevel quality.QualityLevel

	PrimaryFinding     diagnosis.FindingCode
	PrimaryFindingSSRC uint32

	Streams []StreamAnalysis

	EModelAvailable bool
	AverageRFactor  float64
	AverageMOS      float64
}

// AnalyzeCall performs the complete call-level analysis.
//
// mediaMetrics should normally come from
// analyzer.BuildUnifiedMediaMetrics.
//
// When a stream does not have a corresponding unified metrics entry,
// its existing RTP statistics are still analyzed so that missing RTCP
// does not remove the stream from the call-level report.
func AnalyzeCall(
	call analyzer.Call,
	mediaMetrics []analyzer.UnifiedMediaMetrics,
) CallAnalysis {
	result := CallAnalysis{
		EngineVersion: EngineVersion,

		CallID: call.CallID,
		State:  call.State,

		StartTime:     call.StartTime,
		RingingTime:   call.RingingTime,
		ConnectedTime: call.ConnectedTime,
		EndTime:       call.EndTime,

		SetupDurationMs: durationMilliseconds(
			call.SetupDuration,
		),

		CallDurationMs: durationMilliseconds(
			call.Duration,
		),

		FinalResponseCode: call.FinalResponseCode,

		StreamCount: len(call.RTPStreams),

		Streams: make(
			[]StreamAnalysis,
			0,
			len(call.RTPStreams),
		),
	}

	metricsByKey := make(
		map[rtp.StreamKey]analyzer.UnifiedMediaMetrics,
	)

	for _, metrics := range mediaMetrics {
		if metrics.CallID != call.CallID {
			continue
		}

		metricsByKey[metrics.Key] = metrics
	}

	scoreSum := 0.0
	scoreCount := 0

	worstScore := math.Inf(1)

	eModelRSum := 0.0
	eModelMOSSum := 0.0
	eModelCount := 0

	var (
		primaryFinding diagnosis.FindingCode
		primarySSRC    uint32
		primaryRank    int
		primaryConf    float64
		primarySet     bool
	)

	for _, stream := range call.RTPStreams {
		metrics, ok := metricsByKey[stream.Key]

		if !ok {
			metrics = fallbackMediaMetrics(
				call.CallID,
				stream,
			)
		}

		streamFeatures := features.ExtractStreamFeatures(
			metrics,
		)

		qualityResult := quality.AssessStream(
			streamFeatures,
		)

		streamAnalysis := StreamAnalysis{
			Key:         stream.Key,
			PayloadType: stream.PayloadType,

			Metrics:  metrics,
			Features: streamFeatures,
			Quality:  qualityResult,
		}

		if streamFeatures.PacketCount > 0 &&
			qualityResult.Available {

			result.AnalyzedStreamCount++

			scoreSum += qualityResult.Score
			scoreCount++

			if qualityResult.Score < worstScore {
				worstScore = qualityResult.Score
			}

			modelResult, err :=
				emodel.EstimateFromStreamFeatures(
					emodel.DefaultG711Config(),
					streamFeatures,
				)

			if err == nil {
				streamAnalysis.EModelAvailable = true
				streamAnalysis.EModel = modelResult

				eModelRSum += modelResult.RFactor
				eModelMOSSum += modelResult.MOSCQE
				eModelCount++
			}
		}

		var baseline *emodel.Result

		if streamAnalysis.EModelAvailable {
			baseline = &streamAnalysis.EModel
		}

		streamAnalysis.Diagnosis = diagnosis.DiagnoseStream(
			streamFeatures,
			qualityResult,
			baseline,
		)

		candidateFinding,
			candidateRank,
			candidateConfidence,
			ok := selectFindingForCall(
			streamAnalysis.Diagnosis,
		)

		if ok &&
			(!primarySet ||
				candidateRank > primaryRank ||
				(candidateRank == primaryRank &&
					candidateConfidence > primaryConf)) {

			primarySet = true
			primaryFinding = candidateFinding
			primarySSRC = stream.Key.SSRC
			primaryRank = candidateRank
			primaryConf = candidateConfidence
		}

		result.Streams = append(
			result.Streams,
			streamAnalysis,
		)
	}

	if scoreCount > 0 {
		result.AverageScore =
			scoreSum / float64(scoreCount)

		result.OverallScore = worstScore
		result.OverallLevel =
			qualityLevelFromScore(result.OverallScore)
	} else {
		result.AverageScore = 0
		result.OverallScore = 0
		result.OverallLevel = quality.LevelUnknown
	}

	if eModelCount > 0 {
		result.EModelAvailable = true

		result.AverageRFactor =
			eModelRSum / float64(eModelCount)

		result.AverageMOS =
			eModelMOSSum / float64(eModelCount)
	}

	if primarySet {
		result.PrimaryFinding = primaryFinding
		result.PrimaryFindingSSRC = primarySSRC
	}

	return result
}

// AnalyzeCalls analyzes multiple reconstructed calls while preserving
// their original order.
func AnalyzeCalls(
	calls []analyzer.Call,
	mediaMetrics []analyzer.UnifiedMediaMetrics,
) []CallAnalysis {
	if len(calls) == 0 {
		return nil
	}

	results := make(
		[]CallAnalysis,
		0,
		len(calls),
	)

	for _, call := range calls {
		results = append(
			results,
			AnalyzeCall(
				call,
				mediaMetrics,
			),
		)
	}

	return results
}

func fallbackMediaMetrics(
	callID string,
	stream analyzer.RTPStreamResult,
) analyzer.UnifiedMediaMetrics {
	return analyzer.UnifiedMediaMetrics{
		CallID:      callID,
		Key:         stream.Key,
		PayloadType: stream.PayloadType,
		RTP:         stream.Stats,
		HasRTCP:     false,
	}
}

func selectFindingForCall(
	result diagnosis.Result,
) (
	diagnosis.FindingCode,
	int,
	float64,
	bool,
) {
	for _, finding := range result.Findings {
		if !finding.Available {
			continue
		}

		rank := findingSeverityRank(
			finding.Severity,
		)

		if rank <= 0 {
			continue
		}

		return finding.Code,
			rank,
			finding.Confidence,
			true
	}

	return "", 0, 0, false
}

func findingSeverityRank(
	severity diagnosis.Severity,
) int {
	switch severity {
	case diagnosis.SeverityCritical:
		return 3

	case diagnosis.SeverityWarning:
		return 2

	case diagnosis.SeverityInfo:
		return 1

	default:
		return 0
	}
}

func qualityLevelFromScore(
	score float64,
) quality.QualityLevel {
	switch {
	case score >= 90:
		return quality.LevelExcellent

	case score >= 75:
		return quality.LevelGood

	case score >= 60:
		return quality.LevelFair

	case score >= 40:
		return quality.LevelPoor

	default:
		return quality.LevelCritical
	}
}

func durationMilliseconds(
	value time.Duration,
) float64 {
	return float64(value) /
		float64(time.Millisecond)
}
