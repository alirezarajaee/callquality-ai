package pipeline

import (
	"fmt"

	"github.com/alirezarajaee/callquality-ai/app/internal/analyzer"
	"github.com/alirezarajaee/callquality-ai/app/internal/callanalysis"
	"github.com/alirezarajaee/callquality-ai/app/internal/export"
	"github.com/alirezarajaee/callquality-ai/app/internal/ml"
)

// Result contains the complete analysis output produced from one PCAP.
// Packets, Calls, and RTCPResults are retained for CLI/reporting consumers;
// Records and Predictions are the normalized media-level outputs used by
// export and ML consumers.
type Result struct {
	Summary     analyzer.AnalysisSummary
	Packets     []analyzer.AnalyzedPacket
	Calls       []analyzer.Call
	RTCPResults []analyzer.RTCPStreamResult
	CallResults []callanalysis.CallAnalysis
	Records     []export.Record
	Predictions []ml.Prediction
}

// Service runs the complete CallQuality AI analysis pipeline.
// The embedded model is loaded once and then reused across analyses.
type Service struct {
	model *ml.Model
}

// NewService creates an analysis service with the embedded Random Forest model.
func NewService() (*Service, error) {
	model, err := ml.LoadEmbedded()
	if err != nil {
		return nil, fmt.Errorf("load embedded ML model: %w", err)
	}

	return &Service{model: model}, nil
}

// AnalyzeFile parses, reconstructs, scores, diagnoses, exports normalized
// records, and runs native ML inference for one PCAP.
func (service *Service) AnalyzeFile(path string) (Result, error) {
	if service == nil || service.model == nil {
		return Result{}, fmt.Errorf("analysis service is not initialized")
	}

	summary, packets, err := analyzer.AnalyzeFile(path)
	if err != nil {
		return Result{}, err
	}

	calls := analyzer.ReconstructCalls(packets)
	calls = analyzer.AttachRTPStreams(calls, packets)

	rtcpResults := analyzer.CorrelateRTCPWithRTPStreams(calls, packets)
	mediaMetrics := analyzer.BuildUnifiedMediaMetrics(calls, rtcpResults)
	callResults := callanalysis.AnalyzeCalls(calls, mediaMetrics)

	records := export.BuildRecords(calls, callResults)
	predictions := make([]ml.Prediction, 0, len(records))

	for index, record := range records {
		prediction, err := service.model.PredictRecord(record)
		if err != nil {
			return Result{}, fmt.Errorf(
				"predict media stream %d: %w",
				index+1,
				err,
			)
		}

		predictions = append(predictions, prediction)
	}

	return Result{
		Summary:     summary,
		Packets:     packets,
		Calls:       calls,
		RTCPResults: rtcpResults,
		CallResults: callResults,
		Records:     records,
		Predictions: predictions,
	}, nil
}
