package diagnosis

import (
	"sort"

	"github.com/alirezarajaee/callquality-ai/app/internal/emodel"
	"github.com/alirezarajaee/callquality-ai/app/internal/features"
	"github.com/alirezarajaee/callquality-ai/app/internal/quality"
)

// EngineVersion identifies the deterministic diagnosis rules.
const EngineVersion = "1.0"

// Severity represents the impact level of a diagnostic finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// FindingCode identifies a machine-readable diagnosis finding.
type FindingCode string

const (
	FindingHighPacketLoss      FindingCode = "high_packet_loss"
	FindingHighJitter          FindingCode = "high_jitter"
	FindingHighRTT             FindingCode = "high_rtt"
	FindingPacketReordering    FindingCode = "packet_reordering"
	FindingDuplicatePackets    FindingCode = "duplicate_packets"
	FindingRTCPRTPDisagreement FindingCode = "rtcp_rtp_disagreement"
	FindingNoRTCP              FindingCode = "rtcp_unavailable"
	FindingNoJitterMeasurement FindingCode = "jitter_unavailable"
	FindingNoRTTMeasurement    FindingCode = "rtt_unavailable"
)

// Finding is one explainable diagnostic observation.
//
// Confidence is a rule-derived confidence score in the range [0,1].
// It is not a statistical probability and must not be interpreted
// as one.
type Finding struct {
	Code FindingCode

	Severity Severity

	Title       string
	Description string

	Value     float64
	Unit      string
	Threshold float64

	Available  bool
	Confidence float64
}

// Result contains the complete diagnosis for one RTP media stream.
type Result struct {
	EngineVersion string

	CallID string
	SSRC   uint32

	QualityScore float64
	QualityLevel quality.QualityLevel

	PrimaryFinding FindingCode

	Findings []Finding

	EModelAvailable bool
	EModelRFactor   float64
	EModelMOS       float64
}

// DiagnoseStream produces an explainable diagnosis from the extracted
// features, engineering quality assessment, and optional E-model result.
func DiagnoseStream(
	input features.StreamFeatures,
	assessment quality.StreamAssessment,
	baseline *emodel.Result,
) Result {
	result := Result{
		EngineVersion: EngineVersion,

		CallID: input.CallID,
		SSRC:   input.SSRC,

		QualityScore: assessment.Score,
		QualityLevel: assessment.Level,

		Findings: make([]Finding, 0, 8),
	}

	if baseline != nil {
		result.EModelAvailable = true
		result.EModelRFactor = baseline.RFactor
		result.EModelMOS = baseline.MOSCQE
	}

	result.Findings = append(
		result.Findings,
		diagnosePacketLoss(input)...,
	)

	result.Findings = append(
		result.Findings,
		diagnoseJitter(input)...,
	)

	result.Findings = append(
		result.Findings,
		diagnoseRTT(input)...,
	)

	result.Findings = append(
		result.Findings,
		diagnoseReordering(input)...,
	)

	result.Findings = append(
		result.Findings,
		diagnoseDuplicates(input)...,
	)

	result.Findings = append(
		result.Findings,
		diagnoseRTCPAgreement(input)...,
	)

	result.Findings = append(
		result.Findings,
		diagnoseMeasurementAvailability(input)...,
	)

	sortFindings(result.Findings)

	result.PrimaryFinding = selectPrimaryFinding(
		result.Findings,
		assessment.PrimaryFactor,
	)

	return result
}

func diagnosePacketLoss(
	input features.StreamFeatures,
) []Finding {
	loss := input.RTPLossPercent

	if input.HasRTCP > 0 &&
		input.RTCPLossAveragePercent > loss {
		loss = input.RTCPLossAveragePercent
	}

	if loss >= 10 {
		return []Finding{
			{
				Code:        FindingHighPacketLoss,
				Severity:    SeverityCritical,
				Title:       "High packet loss",
				Description: "Packet loss is high enough to be a major media-quality degradation signal.",
				Value:       loss,
				Unit:        "percent",
				Threshold:   10,
				Available:   true,
				Confidence:  0.95,
			},
		}
	}

	if loss >= 5 {
		return []Finding{
			{
				Code:        FindingHighPacketLoss,
				Severity:    SeverityWarning,
				Title:       "Elevated packet loss",
				Description: "Packet loss is elevated and may materially affect media quality.",
				Value:       loss,
				Unit:        "percent",
				Threshold:   5,
				Available:   true,
				Confidence:  0.85,
			},
		}
	}

	return nil
}

func diagnoseJitter(
	input features.StreamFeatures,
) []Finding {
	jitter, available := effectiveJitter(input)

	if !available {
		return nil
	}

	if jitter >= 50 {
		return []Finding{
			{
				Code:        FindingHighJitter,
				Severity:    SeverityCritical,
				Title:       "High jitter",
				Description: "Media arrival-time variation is high and may destabilize playout.",
				Value:       jitter,
				Unit:        "ms",
				Threshold:   50,
				Available:   true,
				Confidence:  0.93,
			},
		}
	}

	if jitter >= 30 {
		return []Finding{
			{
				Code:        FindingHighJitter,
				Severity:    SeverityWarning,
				Title:       "Elevated jitter",
				Description: "Media arrival-time variation is elevated and may reduce media stability.",
				Value:       jitter,
				Unit:        "ms",
				Threshold:   30,
				Available:   true,
				Confidence:  0.82,
			},
		}
	}

	return nil
}

func diagnoseRTT(
	input features.StreamFeatures,
) []Finding {
	rtt, available := effectiveRTT(input)

	if !available {
		return nil
	}

	if rtt >= 300 {
		return []Finding{
			{
				Code:        FindingHighRTT,
				Severity:    SeverityCritical,
				Title:       "High round-trip time",
				Description: "Observed round-trip delay is high and may affect conversational responsiveness.",
				Value:       rtt,
				Unit:        "ms",
				Threshold:   300,
				Available:   true,
				Confidence:  0.92,
			},
		}
	}

	if rtt >= 150 {
		return []Finding{
			{
				Code:        FindingHighRTT,
				Severity:    SeverityWarning,
				Title:       "Elevated round-trip time",
				Description: "Observed round-trip delay is elevated and may affect conversational responsiveness.",
				Value:       rtt,
				Unit:        "ms",
				Threshold:   150,
				Available:   true,
				Confidence:  0.80,
			},
		}
	}

	return nil
}

func diagnoseReordering(
	input features.StreamFeatures,
) []Finding {
	value := 0.0

	if input.PacketCount > 0 {
		value =
			input.OutOfOrderPackets /
				input.PacketCount *
				100
	}

	if value >= 5 {
		return []Finding{
			{
				Code:        FindingPacketReordering,
				Severity:    SeverityCritical,
				Title:       "High packet reordering",
				Description: "A large share of packets arrived out of sequence.",
				Value:       value,
				Unit:        "percent",
				Threshold:   5,
				Available:   true,
				Confidence:  0.88,
			},
		}
	}

	if value >= 2 {
		return []Finding{
			{
				Code:        FindingPacketReordering,
				Severity:    SeverityWarning,
				Title:       "Packet reordering detected",
				Description: "Packets arrived out of sequence often enough to be worth investigating.",
				Value:       value,
				Unit:        "percent",
				Threshold:   2,
				Available:   true,
				Confidence:  0.74,
			},
		}
	}

	return nil
}

func diagnoseDuplicates(
	input features.StreamFeatures,
) []Finding {
	value := 0.0

	if input.PacketCount > 0 {
		value =
			input.DuplicatePackets /
				input.PacketCount *
				100
	}

	if value >= 5 {
		return []Finding{
			{
				Code:        FindingDuplicatePackets,
				Severity:    SeverityCritical,
				Title:       "High duplicate packet rate",
				Description: "A significant share of observed packets were duplicates.",
				Value:       value,
				Unit:        "percent",
				Threshold:   5,
				Available:   true,
				Confidence:  0.86,
			},
		}
	}

	if value >= 1 {
		return []Finding{
			{
				Code:        FindingDuplicatePackets,
				Severity:    SeverityWarning,
				Title:       "Duplicate packets detected",
				Description: "Duplicate RTP packets were observed in the stream.",
				Value:       value,
				Unit:        "percent",
				Threshold:   1,
				Available:   true,
				Confidence:  0.68,
			},
		}
	}

	return nil
}

func diagnoseRTCPAgreement(
	input features.StreamFeatures,
) []Finding {
	if input.HasRTCP <= 0 {
		return nil
	}

	// Prefer the already extracted delta when it exists, but also
	// calculate it directly from the source metrics. This keeps the
	// diagnosis engine robust when it receives a manually constructed
	// feature vector in tests or from another caller.
	delta := input.LossDeltaRTCPvsRTPPercent

	directDelta := absoluteDifference(
		input.RTCPLossAveragePercent,
		input.RTPLossPercent,
	)

	if directDelta > delta {
		delta = directDelta
	}

	if delta >= 5 {
		return []Finding{
			{
				Code:        FindingRTCPRTPDisagreement,
				Severity:    SeverityWarning,
				Title:       "RTP and RTCP loss disagree",
				Description: "RTP-observed loss and RTCP-reported average loss differ materially.",
				Value:       delta,
				Unit:        "percentage points",
				Threshold:   5,
				Available:   true,
				Confidence:  0.72,
			},
		}
	}

	if delta >= 2 {
		return []Finding{
			{
				Code:        FindingRTCPRTPDisagreement,
				Severity:    SeverityInfo,
				Title:       "RTP and RTCP loss differ",
				Description: "RTP-observed and RTCP-reported loss are not identical and should be interpreted in their measurement context.",
				Value:       delta,
				Unit:        "percentage points",
				Threshold:   2,
				Available:   true,
				Confidence:  0.60,
			},
		}
	}

	return nil
}

func diagnoseMeasurementAvailability(
	input features.StreamFeatures,
) []Finding {
	findings := make([]Finding, 0, 3)

	if input.HasRTCP <= 0 {
		findings = append(
			findings,
			Finding{
				Code:        FindingNoRTCP,
				Severity:    SeverityInfo,
				Title:       "RTCP not available",
				Description: "No correlated RTCP observations are available for this stream; RTP-only measurements are being used.",
				Available:   false,
				Confidence:  1,
			},
		)
	}

	_, jitterAvailable := effectiveJitter(input)

	if !jitterAvailable {
		findings = append(
			findings,
			Finding{
				Code:        FindingNoJitterMeasurement,
				Severity:    SeverityInfo,
				Title:       "Jitter measurement unavailable",
				Description: "No usable RTP or RTCP jitter measurement is available for this stream.",
				Available:   false,
				Confidence:  1,
			},
		)
	}

	_, rttAvailable := effectiveRTT(input)

	if !rttAvailable {
		findings = append(
			findings,
			Finding{
				Code:        FindingNoRTTMeasurement,
				Severity:    SeverityInfo,
				Title:       "RTT measurement unavailable",
				Description: "No passive RTT observation is available for this stream.",
				Available:   false,
				Confidence:  1,
			},
		)
	}

	return findings
}

func effectiveJitter(
	input features.StreamFeatures,
) (float64, bool) {
	if input.RTCPJitterAvailableAverage > 0 {
		return input.RTCPJitterAverageMs, true
	}

	if input.RTPJitterAvailable > 0 {
		return input.RTPJitterMs, true
	}

	if input.RTCPJitterAvailableLatest > 0 {
		return input.RTCPJitterLatestMs, true
	}

	return 0, false
}

func effectiveRTT(
	input features.StreamFeatures,
) (float64, bool) {
	if input.RTTAvailableAverage > 0 {
		return input.RTTAverageMs, true
	}

	if input.RTTAvailableLatest > 0 {
		return input.RTTLatestMs, true
	}

	return 0, false
}

func sortFindings(
	findings []Finding,
) {
	sort.SliceStable(
		findings,
		func(i, j int) bool {
			leftSeverity := severityRank(
				findings[i].Severity,
			)

			rightSeverity := severityRank(
				findings[j].Severity,
			)

			if leftSeverity != rightSeverity {
				return leftSeverity > rightSeverity
			}

			if findings[i].Confidence !=
				findings[j].Confidence {

				return findings[i].Confidence >
					findings[j].Confidence
			}

			return findings[i].Code <
				findings[j].Code
		},
	)
}

func selectPrimaryFinding(
	findings []Finding,
	qualityFactor quality.FactorName,
) FindingCode {
	for _, finding := range findings {
		switch qualityFactor {
		case quality.FactorPacketLoss:
			if finding.Code == FindingHighPacketLoss {
				return finding.Code
			}

		case quality.FactorJitter:
			if finding.Code == FindingHighJitter {
				return finding.Code
			}

		case quality.FactorRTT:
			if finding.Code == FindingHighRTT {
				return finding.Code
			}

		case quality.FactorReordering:
			if finding.Code == FindingPacketReordering {
				return finding.Code
			}

		case quality.FactorDuplicates:
			if finding.Code == FindingDuplicatePackets {
				return finding.Code
			}
		}
	}

	for _, finding := range findings {
		if finding.Severity == SeverityCritical ||
			finding.Severity == SeverityWarning {
			return finding.Code
		}
	}

	return ""
}

func severityRank(
	severity Severity,
) int {
	switch severity {
	case SeverityCritical:
		return 3

	case SeverityWarning:
		return 2

	case SeverityInfo:
		return 1

	default:
		return 0
	}
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
