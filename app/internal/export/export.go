package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/alirezarajaee/callquality-ai/app/internal/analyzer"
	"github.com/alirezarajaee/callquality-ai/app/internal/callanalysis"
	"github.com/alirezarajaee/callquality-ai/app/internal/features"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
)

// SchemaVersion is the version of the exported dataset contract.
const SchemaVersion = features.SchemaVersion

// Source describes the input that produced an exported dataset.
type Source struct {
	Capture     string `json:"capture"`
	ToolVersion string `json:"tool_version"`
}

// Document is the JSON dataset envelope.
type Document struct {
	SchemaVersion string   `json:"schema_version"`
	Source        Source   `json:"source"`
	Records       []Record `json:"records"`
}

// Record is one machine-learning-friendly row representing one analyzed
// RTP media stream. Optional measurements use pointers so unavailable
// values are represented as null in JSON and as empty fields in CSV.
type Record struct {
	SchemaVersion string `json:"schema_version"`
	CallID        string `json:"call_id"`
	MediaIndex    int    `json:"media_index"`
	StreamID      string `json:"stream_id"`
	SSRC          uint32 `json:"ssrc"`
	PayloadType   uint8  `json:"payload_type"`
	Codec         string `json:"codec"`
	ClockRate     uint32 `json:"clock_rate"`
	CodecChannels int    `json:"codec_channels"`
	Direction     string `json:"media_direction"`

	SetupDurationMs float64 `json:"setup_duration_ms"`
	CallDurationMs  float64 `json:"call_duration_ms"`

	PacketCount       int64 `json:"packet_count"`
	UniquePackets     int64 `json:"unique_packets"`
	DuplicatePackets  int64 `json:"duplicate_packets"`
	OutOfOrderPackets int64 `json:"out_of_order_packets"`

	ExpectedPackets int64 `json:"expected_packets"`
	LostPackets     int64 `json:"lost_packets"`

	RTPLossPercent float64 `json:"rtp_loss_percent"`
	LossPercent    float64 `json:"loss_percent"`

	ReorderingPercent float64 `json:"reordering_percent"`
	DuplicatePercent  float64 `json:"duplicate_percent"`

	RTPLossAvailable bool     `json:"rtp_loss_available"`
	RTPJitterMs      *float64 `json:"rtp_jitter_ms"`

	RTCPAvailable        bool `json:"rtcp_available"`
	RTCPObservationCount int  `json:"rtcp_observation_count"`

	LatestFractionLostPercent  *float64 `json:"latest_fraction_lost_percent"`
	AverageFractionLostPercent *float64 `json:"average_fraction_lost_percent"`
	LatestCumulativeLost       *int32   `json:"latest_cumulative_lost"`

	LatestJitterMs  *float64 `json:"latest_jitter_ms"`
	AverageJitterMs *float64 `json:"average_jitter_ms"`

	AveragePassiveRTTMs *float64 `json:"average_passive_rtt_ms"`
	LatestPassiveRTTMs  *float64 `json:"latest_passive_rtt_ms"`

	QualityAvailable bool     `json:"quality_available"`
	QualityScore     *float64 `json:"quality_score"`
	QualityLevel     string   `json:"quality_level"`

	EModelAvailable bool     `json:"emodel_available"`
	RFactor         *float64 `json:"r_factor"`
	MOS             *float64 `json:"mos"`

	DiagnosisAvailable  bool     `json:"diagnosis_available"`
	DiagnosisPrimary    string   `json:"diagnosis_primary"`
	DiagnosisSeverity   string   `json:"diagnosis_severity"`
	DiagnosisConfidence *float64 `json:"diagnosis_confidence"`
}

// BuildRecords converts completed call analyses into one record per RTP
// media stream, preserving call order and stream order.
func BuildRecords(calls []analyzer.Call, analyses []callanalysis.CallAnalysis) []Record {
	if len(analyses) == 0 {
		return nil
	}

	callsByID := make(map[string]analyzer.Call, len(calls))
	for _, call := range calls {
		callsByID[call.CallID] = call
	}

	records := make([]Record, 0)
	for _, analysis := range analyses {
		call, ok := callsByID[analysis.CallID]
		if !ok {
			continue
		}

		for _, stream := range analysis.Streams {
			metadata := findMediaMetadata(call, stream)
			records = append(records, buildRecord(call, analysis, stream, metadata))
		}
	}

	return records
}

type mediaMetadata struct {
	mediaIndex int
	codecName  string
	clockRate  uint32
	channels   int
	direction  string
}

func findMediaMetadata(call analyzer.Call, stream callanalysis.StreamAnalysis) mediaMetadata {
	result := mediaMetadata{mediaIndex: -1}

	for _, endpoint := range call.MediaEndpoints {
		if !endpointMatchesStream(endpoint, stream.Key) {
			continue
		}

		result.mediaIndex = endpoint.MediaIndex
		result.direction = strings.TrimSpace(endpoint.Direction)

		codec, ok := endpoint.Codecs[int(stream.PayloadType)]
		if ok {
			result.codecName = strings.TrimSpace(codec.Name)
			result.clockRate = uint32(maxInt(codec.ClockRate, 0))
			result.channels = maxInt(codec.Channels, 0)
		}

		return result
	}

	for _, endpoint := range call.MediaEndpoints {
		codec, ok := endpoint.Codecs[int(stream.PayloadType)]
		if !ok {
			continue
		}

		result.mediaIndex = endpoint.MediaIndex
		result.codecName = strings.TrimSpace(codec.Name)
		result.clockRate = uint32(maxInt(codec.ClockRate, 0))
		result.channels = maxInt(codec.Channels, 0)
		result.direction = strings.TrimSpace(endpoint.Direction)
		return result
	}

	return result
}

func endpointMatchesStream(endpoint analyzer.MediaEndpoint, key rtp.StreamKey) bool {
	if endpoint.Address == key.SourceIP && endpoint.Port == int(key.SourcePort) {
		return true
	}

	if endpoint.Address == key.DestinationIP && endpoint.Port == int(key.DestinationPort) {
		return true
	}

	return false
}

func buildRecord(
	call analyzer.Call,
	callAnalysisResult callanalysis.CallAnalysis,
	stream callanalysis.StreamAnalysis,
	metadata mediaMetadata,
) Record {
	featuresResult := stream.Features

	record := Record{
		SchemaVersion: SchemaVersion,
		CallID:        call.CallID,
		MediaIndex:    metadata.mediaIndex,
		StreamID:      streamID(stream.Key, stream.PayloadType),
		SSRC:          stream.Key.SSRC,
		PayloadType:   stream.PayloadType,
		Codec:         metadata.codecName,
		ClockRate:     uint32(featuresResult.ClockRate),
		CodecChannels: metadata.channels,
		Direction:     metadata.direction,

		SetupDurationMs: callAnalysisResult.SetupDurationMs,
		CallDurationMs:  callAnalysisResult.CallDurationMs,

		PacketCount:       int64(featuresResult.PacketCount),
		UniquePackets:     int64(featuresResult.UniquePackets),
		DuplicatePackets:  int64(featuresResult.DuplicatePackets),
		OutOfOrderPackets: int64(featuresResult.OutOfOrderPackets),
		ExpectedPackets:   int64(featuresResult.ExpectedPackets),
		LostPackets:       int64(featuresResult.LostPackets),

		RTPLossPercent:    featuresResult.RTPLossPercent,
		LossPercent:       stream.Quality.Effective.LossPercent,
		ReorderingPercent: percent(featuresResult.OutOfOrderPackets, featuresResult.PacketCount),
		DuplicatePercent:  percent(featuresResult.DuplicatePackets, featuresResult.PacketCount),

		RTPLossAvailable:     featuresResult.PacketCount > 0,
		RTCPAvailable:        featuresResult.HasRTCP > 0,
		RTCPObservationCount: int(featuresResult.RTCPObservationCount),

		QualityAvailable: stream.Quality.Available,
		QualityLevel:     string(stream.Quality.Level),

		EModelAvailable:  stream.EModelAvailable,
		DiagnosisPrimary: string(stream.Diagnosis.PrimaryFinding),
	}

	if record.ClockRate == 0 && metadata.clockRate > 0 {
		record.ClockRate = metadata.clockRate
	}

	if featuresResult.RTPJitterAvailable > 0 {
		record.RTPJitterMs = ptr(featuresResult.RTPJitterMs)
	}

	if record.RTCPAvailable {
		record.AverageFractionLostPercent = ptr(featuresResult.RTCPLossAveragePercent)
		record.LatestFractionLostPercent = ptr(featuresResult.RTCPLossLatestPercent)
		record.LatestCumulativeLost = ptr(int32(featuresResult.RTCPCumulativeLost))
		if featuresResult.RTCPJitterAvailableAverage > 0 {
			record.AverageJitterMs = ptr(featuresResult.RTCPJitterAverageMs)
		}
		if featuresResult.RTCPJitterAvailableLatest > 0 {
			record.LatestJitterMs = ptr(featuresResult.RTCPJitterLatestMs)
		}
		if featuresResult.RTTAvailableAverage > 0 {
			record.AveragePassiveRTTMs = ptr(featuresResult.RTTAverageMs)
		}
		if featuresResult.RTTAvailableLatest > 0 {
			record.LatestPassiveRTTMs = ptr(featuresResult.RTTLatestMs)
		}
	}

	if record.QualityAvailable {
		record.QualityScore = ptr(stream.Quality.Score)
	}

	if record.EModelAvailable {
		record.RFactor = ptr(stream.EModel.RFactor)
		record.MOS = ptr(stream.EModel.MOSCQE)
	}

	if stream.Diagnosis.PrimaryFinding != "" {
		record.DiagnosisAvailable = true
		for _, finding := range stream.Diagnosis.Findings {
			if finding.Code != stream.Diagnosis.PrimaryFinding || !finding.Available {
				continue
			}

			record.DiagnosisSeverity = string(finding.Severity)
			record.DiagnosisConfidence = ptr(finding.Confidence)
			break
		}
	}

	return record
}

// WriteCSV writes records with a stable header and deterministic numeric formatting.
func WriteCSV(writer io.Writer, records []Record) error {
	if writer == nil {
		return fmt.Errorf("CSV writer is nil")
	}

	csvWriter := csv.NewWriter(writer)
	if err := csvWriter.Write(csvHeaders()); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}

	for _, record := range records {
		if err := csvWriter.Write(recordCSVValues(record)); err != nil {
			return fmt.Errorf("write CSV record: %w", err)
		}
	}

	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("flush CSV: %w", err)
	}

	return nil
}

// WriteJSON writes a stable JSON dataset envelope.
func WriteJSON(writer io.Writer, source Source, records []Record) error {
	if writer == nil {
		return fmt.Errorf("JSON writer is nil")
	}

	document := Document{
		SchemaVersion: SchemaVersion,
		Source:        source,
		Records:       records,
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}

	return nil
}

func csvHeaders() []string {
	return []string{
		"schema_version",
		"call_id",
		"media_index",
		"stream_id",
		"ssrc",
		"payload_type",
		"codec",
		"clock_rate",
		"codec_channels",
		"media_direction",
		"setup_duration_ms",
		"call_duration_ms",
		"packet_count",
		"unique_packets",
		"duplicate_packets",
		"out_of_order_packets",
		"expected_packets",
		"lost_packets",
		"rtp_loss_percent",
		"loss_percent",
		"reordering_percent",
		"duplicate_percent",
		"rtp_loss_available",
		"rtp_jitter_ms",
		"rtcp_available",
		"rtcp_observation_count",
		"latest_fraction_lost_percent",
		"average_fraction_lost_percent",
		"latest_cumulative_lost",
		"latest_jitter_ms",
		"average_jitter_ms",
		"average_passive_rtt_ms",
		"latest_passive_rtt_ms",
		"quality_available",
		"quality_score",
		"quality_level",
		"emodel_available",
		"r_factor",
		"mos",
		"diagnosis_available",
		"diagnosis_primary",
		"diagnosis_severity",
		"diagnosis_confidence",
	}
}

func recordCSVValues(record Record) []string {
	return []string{
		record.SchemaVersion,
		record.CallID,
		strconv.Itoa(record.MediaIndex),
		record.StreamID,
		strconv.FormatUint(uint64(record.SSRC), 10),
		strconv.Itoa(int(record.PayloadType)),
		record.Codec,
		strconv.FormatUint(uint64(record.ClockRate), 10),
		strconv.Itoa(record.CodecChannels),
		record.Direction,
		floatString(record.SetupDurationMs),
		floatString(record.CallDurationMs),
		strconv.FormatInt(record.PacketCount, 10),
		strconv.FormatInt(record.UniquePackets, 10),
		strconv.FormatInt(record.DuplicatePackets, 10),
		strconv.FormatInt(record.OutOfOrderPackets, 10),
		strconv.FormatInt(record.ExpectedPackets, 10),
		strconv.FormatInt(record.LostPackets, 10),
		floatString(record.RTPLossPercent),
		floatString(record.LossPercent),
		floatString(record.ReorderingPercent),
		floatString(record.DuplicatePercent),
		boolFlag(record.RTPLossAvailable),
		ptrFloatString(record.RTPJitterMs),
		boolFlag(record.RTCPAvailable),
		strconv.Itoa(record.RTCPObservationCount),
		ptrFloatString(record.LatestFractionLostPercent),
		ptrFloatString(record.AverageFractionLostPercent),
		ptrInt32String(record.LatestCumulativeLost),
		ptrFloatString(record.LatestJitterMs),
		ptrFloatString(record.AverageJitterMs),
		ptrFloatString(record.AveragePassiveRTTMs),
		ptrFloatString(record.LatestPassiveRTTMs),
		boolFlag(record.QualityAvailable),
		ptrFloatString(record.QualityScore),
		record.QualityLevel,
		boolFlag(record.EModelAvailable),
		ptrFloatString(record.RFactor),
		ptrFloatString(record.MOS),
		boolFlag(record.DiagnosisAvailable),
		record.DiagnosisPrimary,
		record.DiagnosisSeverity,
		ptrFloatString(record.DiagnosisConfidence),
	}
}

func floatString(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func ptrFloatString(value *float64) string {
	if value == nil {
		return ""
	}
	return floatString(*value)
}

func ptrInt32String(value *int32) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(int64(*value), 10)
}

func boolFlag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func percent(numerator, denominator float64) float64 {
	if denominator <= 0 {
		return 0
	}
	return numerator / denominator * 100
}

func streamID(key rtp.StreamKey, payloadType uint8) string {
	return fmt.Sprintf(
		"%08x:%s:%d->%s:%d:pt%d",
		key.SSRC,
		key.SourceIP,
		key.SourcePort,
		key.DestinationIP,
		key.DestinationPort,
		payloadType,
	)
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func ptr[T any](value T) *T {
	return &value
}
