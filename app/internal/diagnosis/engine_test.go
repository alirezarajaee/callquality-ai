package diagnosis

import (
	"math"
	"testing"

	"github.com/alirezarajaee/callquality-ai/app/internal/emodel"
	"github.com/alirezarajaee/callquality-ai/app/internal/features"
	"github.com/alirezarajaee/callquality-ai/app/internal/quality"
)

func TestDiagnoseStreamHighPacketLoss(t *testing.T) {
	input := features.StreamFeatures{
		CallID:             "call-loss",
		SSRC:               0x11111111,
		PacketCount:        1000,
		RTPLossPercent:     12,
		RTPJitterAvailable: 1,
		RTPJitterMs:        10,
	}

	assessment := quality.AssessStream(input)

	result := DiagnoseStream(
		input,
		assessment,
		nil,
	)

	if result.EngineVersion != EngineVersion {
		t.Fatalf(
			"engine version mismatch: got %q want %q",
			result.EngineVersion,
			EngineVersion,
		)
	}

	if result.CallID != "call-loss" {
		t.Fatalf(
			"call ID mismatch: got %q",
			result.CallID,
		)
	}

	if result.PrimaryFinding != FindingHighPacketLoss {
		t.Fatalf(
			"primary finding mismatch: got %q want %q",
			result.PrimaryFinding,
			FindingHighPacketLoss,
		)
	}

	finding, ok := findFinding(
		result.Findings,
		FindingHighPacketLoss,
	)

	if !ok {
		t.Fatal("expected high packet loss finding")
	}

	if finding.Severity != SeverityCritical {
		t.Fatalf(
			"severity mismatch: got %q want %q",
			finding.Severity,
			SeverityCritical,
		)
	}

	if math.Abs(finding.Value-12) > 1e-12 {
		t.Fatalf(
			"loss value mismatch: got %.12f",
			finding.Value,
		)
	}

	if finding.Confidence < 0.9 {
		t.Fatalf(
			"unexpected confidence: %.6f",
			finding.Confidence,
		)
	}
}

func TestDiagnoseStreamHighJitter(t *testing.T) {
	input := features.StreamFeatures{
		CallID:             "call-jitter",
		SSRC:               0x22222222,
		PacketCount:        1000,
		RTPLossPercent:     1,
		RTPJitterAvailable: 1,
		RTPJitterMs:        65,
	}

	assessment := quality.AssessStream(input)

	result := DiagnoseStream(
		input,
		assessment,
		nil,
	)

	finding, ok := findFinding(
		result.Findings,
		FindingHighJitter,
	)

	if !ok {
		t.Fatal("expected high jitter finding")
	}

	if finding.Severity != SeverityCritical {
		t.Fatalf(
			"severity mismatch: got %q want %q",
			finding.Severity,
			SeverityCritical,
		)
	}

	if result.PrimaryFinding != FindingHighJitter {
		t.Fatalf(
			"primary finding mismatch: got %q want %q",
			result.PrimaryFinding,
			FindingHighJitter,
		)
	}
}

func TestDiagnoseStreamHighRTT(t *testing.T) {
	input := features.StreamFeatures{
		CallID:              "call-rtt",
		SSRC:                0x33333333,
		PacketCount:         1000,
		RTPLossPercent:      1,
		RTTAvailableAverage: 1,
		RTTAverageMs:        350,
	}

	assessment := quality.AssessStream(input)

	result := DiagnoseStream(
		input,
		assessment,
		nil,
	)

	finding, ok := findFinding(
		result.Findings,
		FindingHighRTT,
	)

	if !ok {
		t.Fatal("expected high RTT finding")
	}

	if finding.Severity != SeverityCritical {
		t.Fatalf(
			"severity mismatch: got %q want %q",
			finding.Severity,
			SeverityCritical,
		)
	}
}

func TestDiagnoseStreamReorderingAndDuplicates(t *testing.T) {
	input := features.StreamFeatures{
		CallID:            "call-order",
		SSRC:              0x44444444,
		PacketCount:       1000,
		RTPLossPercent:    1,
		OutOfOrderPackets: 60,
		DuplicatePackets:  60,
	}

	assessment := quality.AssessStream(input)

	result := DiagnoseStream(
		input,
		assessment,
		nil,
	)

	reordering, ok := findFinding(
		result.Findings,
		FindingPacketReordering,
	)

	if !ok {
		t.Fatal("expected packet reordering finding")
	}

	if reordering.Severity != SeverityCritical {
		t.Fatalf(
			"reordering severity mismatch: got %q",
			reordering.Severity,
		)
	}

	duplicates, ok := findFinding(
		result.Findings,
		FindingDuplicatePackets,
	)

	if !ok {
		t.Fatal("expected duplicate packet finding")
	}

	if duplicates.Severity != SeverityCritical {
		t.Fatalf(
			"duplicate severity mismatch: got %q",
			duplicates.Severity,
		)
	}
}

func TestDiagnoseStreamRTCPRTPDisagreement(t *testing.T) {
	input := features.StreamFeatures{
		CallID:                 "call-disagreement",
		SSRC:                   0x55555555,
		PacketCount:            1000,
		RTPLossPercent:         2,
		HasRTCP:                1,
		RTCPLossAveragePercent: 8,
		RTPJitterAvailable:     1,
		RTPJitterMs:            5,
	}

	assessment := quality.AssessStream(input)

	result := DiagnoseStream(
		input,
		assessment,
		nil,
	)

	finding, ok := findFinding(
		result.Findings,
		FindingRTCPRTPDisagreement,
	)

	if !ok {
		t.Fatal("expected RTCP/RTP disagreement finding")
	}

	if finding.Severity != SeverityWarning {
		t.Fatalf(
			"severity mismatch: got %q want %q",
			finding.Severity,
			SeverityWarning,
		)
	}

	if math.Abs(finding.Value-6) > 1e-12 {
		t.Fatalf(
			"disagreement value mismatch: got %.12f",
			finding.Value,
		)
	}
}

func TestDiagnoseStreamUsesEModelBaseline(t *testing.T) {
	input := features.StreamFeatures{
		CallID:         "call-emodel",
		SSRC:           0x66666666,
		PacketCount:    1000,
		RTPLossPercent: 1,
	}

	assessment := quality.AssessStream(input)

	baseline := &emodel.Result{
		ModelVersion: "test",
		RFactor:      82.5,
		MOSCQE:       4.02,
	}

	result := DiagnoseStream(
		input,
		assessment,
		baseline,
	)

	if !result.EModelAvailable {
		t.Fatal("expected E-model to be available")
	}

	if math.Abs(result.EModelRFactor-82.5) > 1e-12 {
		t.Fatalf(
			"R-factor mismatch: got %.12f",
			result.EModelRFactor,
		)
	}

	if math.Abs(result.EModelMOS-4.02) > 1e-12 {
		t.Fatalf(
			"MOS mismatch: got %.12f",
			result.EModelMOS,
		)
	}
}

func TestDiagnoseStreamReportsUnavailableMeasurements(t *testing.T) {
	input := features.StreamFeatures{
		CallID:                     "call-partial",
		SSRC:                       0x77777777,
		PacketCount:                100,
		RTPLossPercent:             0.5,
		HasRTCP:                    0,
		RTPJitterAvailable:         0,
		RTCPJitterAvailableAverage: 0,
		RTCPJitterAvailableLatest:  0,
		RTTAvailableAverage:        0,
		RTTAvailableLatest:         0,
	}

	assessment := quality.AssessStream(input)

	result := DiagnoseStream(
		input,
		assessment,
		nil,
	)

	noRTCP, ok := findFinding(
		result.Findings,
		FindingNoRTCP,
	)

	if !ok {
		t.Fatal("expected RTCP unavailable finding")
	}

	if noRTCP.Severity != SeverityInfo {
		t.Fatalf(
			"RTCP availability severity mismatch: got %q",
			noRTCP.Severity,
		)
	}

	noJitter, ok := findFinding(
		result.Findings,
		FindingNoJitterMeasurement,
	)

	if !ok {
		t.Fatal("expected jitter unavailable finding")
	}

	if noJitter.Severity != SeverityInfo {
		t.Fatalf(
			"jitter availability severity mismatch: got %q",
			noJitter.Severity,
		)
	}

	noRTT, ok := findFinding(
		result.Findings,
		FindingNoRTTMeasurement,
	)

	if !ok {
		t.Fatal("expected RTT unavailable finding")
	}

	if noRTT.Severity != SeverityInfo {
		t.Fatalf(
			"RTT availability severity mismatch: got %q",
			noRTT.Severity,
		)
	}
}

func TestDiagnoseStreamUsesRTCPJitterWhenAvailable(t *testing.T) {
	input := features.StreamFeatures{
		CallID:                     "call-rtcp-jitter",
		SSRC:                       0x88888888,
		PacketCount:                1000,
		RTPLossPercent:             1,
		RTPJitterAvailable:         1,
		RTPJitterMs:                10,
		HasRTCP:                    1,
		RTCPJitterAvailableAverage: 1,
		RTCPJitterAverageMs:        60,
	}

	assessment := quality.AssessStream(input)

	result := DiagnoseStream(
		input,
		assessment,
		nil,
	)

	finding, ok := findFinding(
		result.Findings,
		FindingHighJitter,
	)

	if !ok {
		t.Fatal("expected high jitter finding from RTCP jitter")
	}

	if math.Abs(finding.Value-60) > 1e-12 {
		t.Fatalf(
			"jitter value mismatch: got %.12f",
			finding.Value,
		)
	}
}

func TestDiagnoseStreamCleanCallHasNoCriticalFindings(t *testing.T) {
	input := features.StreamFeatures{
		CallID:                 "call-clean",
		SSRC:                   0x99999999,
		PacketCount:            1000,
		RTPLossPercent:         0.1,
		RTPJitterAvailable:     1,
		RTPJitterMs:            5,
		RTTAvailableAverage:    1,
		RTTAverageMs:           30,
		HasRTCP:                1,
		RTCPLossAveragePercent: 0.1,
	}

	assessment := quality.AssessStream(input)

	result := DiagnoseStream(
		input,
		assessment,
		nil,
	)

	for _, finding := range result.Findings {
		if finding.Severity == SeverityCritical {
			t.Fatalf(
				"unexpected critical finding: %q",
				finding.Code,
			)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank(SeverityCritical) <=
		severityRank(SeverityWarning) {
		t.Fatal("critical must rank above warning")
	}

	if severityRank(SeverityWarning) <=
		severityRank(SeverityInfo) {
		t.Fatal("warning must rank above info")
	}
}

func TestFindFinding(t *testing.T) {
	findings := []Finding{
		{
			Code:     FindingHighJitter,
			Severity: SeverityWarning,
		},
		{
			Code:     FindingHighRTT,
			Severity: SeverityCritical,
		},
	}

	found, ok := findFinding(
		findings,
		FindingHighRTT,
	)

	if !ok {
		t.Fatal("expected finding")
	}

	if found.Code != FindingHighRTT {
		t.Fatalf(
			"finding mismatch: got %q",
			found.Code,
		)
	}
}

func findFinding(
	findings []Finding,
	code FindingCode,
) (Finding, bool) {
	for _, finding := range findings {
		if finding.Code == code {
			return finding, true
		}
	}

	return Finding{}, false
}
