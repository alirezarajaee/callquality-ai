package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alirezarajaee/callquality-ai/app/internal/analyzer"
	"github.com/alirezarajaee/callquality-ai/app/internal/callanalysis"
	"github.com/alirezarajaee/callquality-ai/app/internal/diagnosis"
	"github.com/alirezarajaee/callquality-ai/app/internal/features"
	"github.com/alirezarajaee/callquality-ai/app/internal/quality"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
	"github.com/alirezarajaee/callquality-ai/app/internal/sdp"
)

func TestBuildRecordsUsesSDPCodecMetadata(t *testing.T) {
	keyA := rtp.StreamKey{
		SSRC:            0x11111111,
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.2",
		SourcePort:      10000,
		DestinationPort: 20000,
	}

	keyB := rtp.StreamKey{
		SSRC:            0x22222222,
		SourceIP:        "10.0.0.2",
		DestinationIP:   "10.0.0.1",
		SourcePort:      20000,
		DestinationPort: 10000,
	}

	metricsA := analyzer.UnifiedMediaMetrics{
		CallID:      "call-001",
		Key:         keyA,
		PayloadType: 0,
		ClockRate:   8000,
		RTP: rtp.StreamStats{
			Key:                keyA,
			PacketCount:        49,
			UniquePackets:      49,
			ExpectedPackets:    50,
			LostPackets:        1,
			LossPercent:        2,
			JitterAvailable:    true,
			JitterMilliseconds: 8,
		},
		HasRTCP:                    true,
		RTCPObservationCount:       2,
		AverageFractionLostPercent: 2,
		LatestFractionLostPercent:  2,
		AverageJitterMilliseconds:  9,
		LatestJitterMilliseconds:   10,
		AverageJitterAvailable:     true,
		LatestJitterAvailable:      true,
		AveragePassiveRTTSeconds:   0.08,
		LatestPassiveRTTSeconds:    0.1,
		AveragePassiveRTTAvailable: true,
		LatestPassiveRTTAvailable:  true,
	}

	metricsB := metricsA
	metricsB.Key = keyB

	featuresA := features.ExtractStreamFeatures(metricsA)
	qualityA := quality.AssessStream(featuresA)

	featuresB := features.ExtractStreamFeatures(metricsB)
	qualityB := quality.AssessStream(featuresB)

	analysis := callanalysis.CallAnalysis{
		CallID:          "call-001",
		SetupDurationMs: 200,
		CallDurationMs:  5000,
		Streams: []callanalysis.StreamAnalysis{
			{
				Key:         keyA,
				PayloadType: 0,
				Metrics:     metricsA,
				Features:    featuresA,
				Quality:     qualityA,
			},
			{
				Key:         keyB,
				PayloadType: 0,
				Metrics:     metricsB,
				Features:    featuresB,
				Quality:     qualityB,
			},
		},
	}

	call := analyzer.Call{
		CallID: "call-001",
		MediaEndpoints: []analyzer.MediaEndpoint{
			{
				MediaIndex: 0,
				MediaType:  "audio",
				Address:    "10.0.0.1",
				Port:       10000,
				Protocol:   "RTP/AVP",
				Codecs: map[int]sdp.CodecInfo{
					0: {
						PayloadType: 0,
						Name:        "PCMU",
						ClockRate:   8000,
						Channels:    1,
					},
				},
			},
			{
				MediaIndex: 0,
				MediaType:  "audio",
				Address:    "10.0.0.2",
				Port:       20000,
				Protocol:   "RTP/AVP",
				Codecs: map[int]sdp.CodecInfo{
					0: {
						PayloadType: 0,
						Name:        "PCMU",
						ClockRate:   8000,
						Channels:    1,
					},
				},
			},
		},
	}

	records := BuildRecords(
		[]analyzer.Call{call},
		[]callanalysis.CallAnalysis{analysis},
	)

	if len(records) != 2 {
		t.Fatalf("record count mismatch: got %d want 2", len(records))
	}

	for _, record := range records {
		if record.Codec != "PCMU" {
			t.Fatalf("codec mismatch: got %q", record.Codec)
		}
		if record.ClockRate != 8000 {
			t.Fatalf("clock rate mismatch: got %d", record.ClockRate)
		}
		if record.PayloadType != 0 {
			t.Fatalf("payload type mismatch: got %d", record.PayloadType)
		}
		if record.RTPJitterMs == nil {
			t.Fatal("expected RTP jitter")
		}
		if record.AveragePassiveRTTMs == nil {
			t.Fatal("expected average passive RTT")
		}
	}
}

func TestWriteCSVStableHeaderAndOptionalFields(t *testing.T) {
	qualityScore := 78.24

	record := Record{
		SchemaVersion:    SchemaVersion,
		CallID:           "call,001",
		MediaIndex:       0,
		StreamID:         "stream-1",
		SSRC:             1,
		PayloadType:      0,
		Codec:            "PCMU",
		ClockRate:        8000,
		CodecChannels:    1,
		Direction:        "sendrecv",
		SetupDurationMs:  200,
		CallDurationMs:   5000,
		PacketCount:      49,
		QualityAvailable: true,
		QualityScore:     &qualityScore,
		QualityLevel:     "good",
		RTCPAvailable:    false,
	}

	var first bytes.Buffer
	if err := WriteCSV(&first, []Record{record}); err != nil {
		t.Fatalf("WriteCSV returned error: %v", err)
	}

	output := first.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header plus one row, got %d lines", len(lines))
	}

	if !strings.Contains(lines[0], "schema_version,call_id,media_index") {
		t.Fatalf("unexpected header: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"call,001"`) {
		t.Fatalf("CSV escaping missing: %s", lines[1])
	}
	parsed, err := csv.NewReader(strings.NewReader(output)).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse generated CSV: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected two CSV records, got %d", len(parsed))
	}
	if got := parsed[1][1]; got != "call,001" {
		t.Fatalf("escaped call ID mismatch: %q", got)
	}
	if got := parsed[1][24]; got != "0" {
		t.Fatalf("expected RTCP availability flag 0, got %q", got)
	}
	if got := parsed[1][33]; got != "1" {
		t.Fatalf("expected quality availability flag 1, got %q", got)
	}
	if got := parsed[1][34]; got != "78.24" {
		t.Fatalf("expected quality score 78.24, got %q", got)
	}

	var second bytes.Buffer
	if err := WriteCSV(&second, []Record{record}); err != nil {
		t.Fatalf("second WriteCSV returned error: %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("CSV output is not deterministic")
	}
}

func TestWriteJSONStableAndVersioned(t *testing.T) {
	record := Record{
		SchemaVersion: SchemaVersion,
		CallID:        "call-001",
		SSRC:          0x11111111,
		PayloadType:   0,
		Codec:         "PCMU",
		ClockRate:     8000,
		RTCPAvailable: false,
	}

	var first bytes.Buffer
	if err := WriteJSON(
		&first,
		Source{Capture: "sample.pcap", ToolVersion: "0.1.0"},
		[]Record{record},
	); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var document Document
	if err := json.Unmarshal(first.Bytes(), &document); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if document.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version mismatch: got %q", document.SchemaVersion)
	}
	if len(document.Records) != 1 {
		t.Fatalf("record count mismatch: got %d", len(document.Records))
	}
	if document.Records[0].RTPJitterMs != nil {
		t.Fatal("expected unavailable RTP jitter to be null")
	}

	var second bytes.Buffer
	if err := WriteJSON(
		&second,
		Source{Capture: "sample.pcap", ToolVersion: "0.1.0"},
		[]Record{record},
	); err != nil {
		t.Fatalf("second WriteJSON returned error: %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("JSON output is not deterministic")
	}
}

func TestBuildRecordsSkipsAnalysisWithoutMatchingCall(t *testing.T) {
	analysis := callanalysis.CallAnalysis{
		CallID: "missing-call",
		Streams: []callanalysis.StreamAnalysis{
			{
				Key:         rtp.StreamKey{SSRC: 1},
				PayloadType: 0,
				Features:    features.StreamFeatures{CallID: "missing-call"},
			},
		},
	}

	records := BuildRecords(nil, []callanalysis.CallAnalysis{analysis})
	if len(records) != 0 {
		t.Fatalf("expected no records, got %d", len(records))
	}
}

func TestDiagnosisMetadata(t *testing.T) {
	confidence := 0.85
	_ = confidence
	finding := diagnosis.Finding{
		Code:       diagnosis.FindingHighPacketLoss,
		Severity:   diagnosis.SeverityWarning,
		Available:  true,
		Confidence: 0.85,
	}

	record := Record{
		DiagnosisAvailable:  true,
		DiagnosisPrimary:    string(finding.Code),
		DiagnosisSeverity:   string(finding.Severity),
		DiagnosisConfidence: &confidence,
	}

	if record.DiagnosisPrimary != "high_packet_loss" {
		t.Fatalf("unexpected diagnosis code: %s", record.DiagnosisPrimary)
	}
	if record.DiagnosisSeverity != "warning" {
		t.Fatalf("unexpected diagnosis severity: %s", record.DiagnosisSeverity)
	}
}
