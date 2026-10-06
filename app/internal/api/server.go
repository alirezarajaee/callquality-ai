package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/alirezarajaee/callquality-ai/app/internal/callanalysis"
	"github.com/alirezarajaee/callquality-ai/app/internal/diagnosis"
	"github.com/alirezarajaee/callquality-ai/app/internal/export"
	"github.com/alirezarajaee/callquality-ai/app/internal/ml"
	"github.com/alirezarajaee/callquality-ai/app/internal/pipeline"
	"github.com/alirezarajaee/callquality-ai/app/internal/quality"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
)

const (
	APIVersion       = "1"
	DefaultMaxUpload = 64 << 20
)

// Config configures the local HTTP API server.
type Config struct {
	MaxUploadBytes int64
}

// NewServer creates the local CallQuality AI HTTP API.
func NewServer(service *pipeline.Service, config Config) (http.Handler, error) {
	if service == nil {
		return nil, fmt.Errorf("analysis service is nil")
	}

	if config.MaxUploadBytes <= 0 {
		config.MaxUploadBytes = DefaultMaxUpload
	}

	handler := &server{
		service:        service,
		maxUploadBytes: config.MaxUploadBytes,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", handler.handleHealth)
	mux.HandleFunc("/api/v1/version", handler.handleVersion)
	mux.HandleFunc("/api/v1/analyze", handler.handleAnalyze)
	mux.HandleFunc("/", handler.handleNotFound)

	return withCORS(mux), nil
}

type server struct {
	service        *pipeline.Service
	maxUploadBytes int64
}

type errorResponse struct {
	Error APIError `json:"error"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type healthResponse struct {
	Status string `json:"status"`
}

type versionResponse struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
	MLModel    string `json:"ml_model"`
}

type analyzeResponse struct {
	SchemaVersion string          `json:"schema_version"`
	Source        sourceResponse  `json:"source"`
	Capture       captureResponse `json:"capture"`
	Calls         []callResponse  `json:"calls"`
}

type sourceResponse struct {
	Filename string `json:"filename"`
}

type captureResponse struct {
	PacketsAnalyzed    int `json:"packets_analyzed"`
	SIPPackets         int `json:"sip_packets"`
	SIPRequests        int `json:"sip_requests"`
	SIPResponses       int `json:"sip_responses"`
	CallsReconstructed int `json:"calls_reconstructed"`
	RTCPStreams        int `json:"rtcp_streams"`
}

type callResponse struct {
	CallID               string           `json:"call_id"`
	State                string           `json:"state"`
	SetupDurationMs      float64          `json:"setup_duration_ms"`
	CallDurationMs       float64          `json:"call_duration_ms"`
	FinalResponseCode    int              `json:"final_response_code"`
	StreamCount          int              `json:"stream_count"`
	AnalyzedStreamCount  int              `json:"analyzed_stream_count"`
	AverageScore         *float64         `json:"average_score"`
	OverallScore         *float64         `json:"overall_score"`
	OverallLevel         string           `json:"overall_level"`
	AverageRFactor       *float64         `json:"average_r_factor"`
	AverageMOS           *float64         `json:"average_mos"`
	PrimaryDiagnosis     string           `json:"primary_diagnosis"`
	PrimaryDiagnosisSSRC *uint32          `json:"primary_diagnosis_ssrc"`
	Streams              []streamResponse `json:"streams"`
}

type streamResponse struct {
	SSRC           uint32            `json:"ssrc"`
	MediaIndex     int               `json:"media_index"`
	StreamID       string            `json:"stream_id"`
	PayloadType    uint8             `json:"payload_type"`
	Codec          string            `json:"codec"`
	ClockRate      uint32            `json:"clock_rate"`
	CodecChannels  int               `json:"codec_channels"`
	MediaDirection string            `json:"media_direction"`
	RTP            rtpResponse       `json:"rtp"`
	RTCP           rtcpResponse      `json:"rtcp"`
	Quality        qualityResponse   `json:"quality"`
	EModel         emodelResponse    `json:"emodel"`
	Diagnosis      diagnosisResponse `json:"diagnosis"`
	ML             mlResponse        `json:"ml"`
}

type rtpResponse struct {
	PacketCount       int64    `json:"packet_count"`
	UniquePackets     int64    `json:"unique_packets"`
	DuplicatePackets  int64    `json:"duplicate_packets"`
	OutOfOrderPackets int64    `json:"out_of_order_packets"`
	ExpectedPackets   int64    `json:"expected_packets"`
	LostPackets       int64    `json:"lost_packets"`
	LossPercent       float64  `json:"loss_percent"`
	JitterMs          *float64 `json:"jitter_ms"`
}

type rtcpResponse struct {
	Available           bool     `json:"available"`
	ObservationCount    int      `json:"observation_count"`
	LatestLossPercent   *float64 `json:"latest_loss_percent"`
	AverageLossPercent  *float64 `json:"average_loss_percent"`
	LatestJitterMs      *float64 `json:"latest_jitter_ms"`
	AverageJitterMs     *float64 `json:"average_jitter_ms"`
	LatestPassiveRTTMs  *float64 `json:"latest_passive_rtt_ms"`
	AveragePassiveRTTMs *float64 `json:"average_passive_rtt_ms"`
}

type qualityResponse struct {
	Available     bool                     `json:"available"`
	Score         *float64                 `json:"score"`
	Level         string                   `json:"level"`
	PrimaryFactor string                   `json:"primary_factor"`
	Effective     qualityEffectiveResponse `json:"effective"`
	Factors       []qualityFactorResponse  `json:"factors"`
}

type qualityEffectiveResponse struct {
	LossPercent       float64 `json:"loss_percent"`
	LossSource        string  `json:"loss_source"`
	JitterMs          float64 `json:"jitter_ms"`
	JitterSource      string  `json:"jitter_source"`
	RTTMs             float64 `json:"rtt_ms"`
	RTTSource         string  `json:"rtt_source"`
	OutOfOrderPercent float64 `json:"out_of_order_percent"`
	DuplicatePercent  float64 `json:"duplicate_percent"`
}

type qualityFactorResponse struct {
	Name      string  `json:"name"`
	Value     float64 `json:"value"`
	Unit      string  `json:"unit"`
	Penalty   float64 `json:"penalty"`
	Available bool    `json:"available"`
}

type emodelResponse struct {
	Available         bool     `json:"available"`
	ModelVersion      string   `json:"model_version,omitempty"`
	RFactor           *float64 `json:"r_factor,omitempty"`
	MOS               *float64 `json:"mos,omitempty"`
	OneWayDelayMs     *float64 `json:"one_way_delay_ms,omitempty"`
	PacketLossPercent *float64 `json:"packet_loss_percent,omitempty"`
	DelaySource       string   `json:"delay_source,omitempty"`
	LossSource        string   `json:"loss_source,omitempty"`
}

type diagnosisResponse struct {
	Available      bool              `json:"available"`
	PrimaryFinding string            `json:"primary_finding,omitempty"`
	QualityLevel   string            `json:"quality_level,omitempty"`
	QualityScore   *float64          `json:"quality_score,omitempty"`
	Findings       []findingResponse `json:"findings"`
}

type findingResponse struct {
	Code        string  `json:"code"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Value       float64 `json:"value"`
	Unit        string  `json:"unit"`
	Threshold   float64 `json:"threshold"`
	Available   bool    `json:"available"`
	Confidence  float64 `json:"confidence"`
}

type mlResponse struct {
	ModelVersion   string                  `json:"model_version"`
	PredictedClass string                  `json:"predicted_class"`
	MaxClassVote   float64                 `json:"max_class_vote"`
	Probabilities  []mlProbabilityResponse `json:"probabilities"`
}

type mlProbabilityResponse struct {
	Class string  `json:"class"`
	Value float64 `json:"value"`
}

func (handler *server) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeMethodNotAllowed(writer)
		return
	}

	writeJSON(writer, http.StatusOK, healthResponse{Status: "ok"})
}

func (handler *server) handleVersion(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeMethodNotAllowed(writer)
		return
	}

	writeJSON(writer, http.StatusOK, versionResponse{
		Name:       "CallQuality AI",
		Version:    "0.1.0",
		APIVersion: APIVersion,
		MLModel:    "Random Forest v1",
	})
}

func (handler *server) handleAnalyze(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(writer)
		return
	}

	request.Body = http.MaxBytesReader(
		writer,
		request.Body,
		handler.maxUploadBytes+1,
	)

	tempPath, originalFilename, err := saveUploadedPCAP(
		request,
		handler.maxUploadBytes,
	)
	if err != nil {
		var httpErr *requestError
		if errors.As(err, &httpErr) {
			writeError(writer, httpErr.status, httpErr.code, httpErr.message)
			return
		}

		writeError(
			writer,
			http.StatusBadRequest,
			"invalid_request",
			err.Error(),
		)
		return
	}

	defer os.Remove(tempPath)

	result, err := handler.service.AnalyzeFile(tempPath)
	if err != nil {
		writeError(
			writer,
			http.StatusUnprocessableEntity,
			"analysis_failed",
			err.Error(),
		)
		return
	}

	response := buildAnalyzeResponse(
		originalFilename,
		result,
	)

	writeJSON(writer, http.StatusOK, response)
}

func (handler *server) handleNotFound(writer http.ResponseWriter, request *http.Request) {
	writeError(
		writer,
		http.StatusNotFound,
		"not_found",
		"endpoint not found",
	)
}

func saveUploadedPCAP(
	request *http.Request,
	maxBytes int64,
) (string, string, error) {
	contentType := request.Header.Get("Content-Type")
	if !strings.HasPrefix(
		strings.ToLower(contentType),
		"multipart/form-data",
	) {
		return "", "", &requestError{
			status:  http.StatusUnsupportedMediaType,
			code:    "invalid_content_type",
			message: "Content-Type must be multipart/form-data",
		}
	}

	reader, err := request.MultipartReader()
	if err != nil {
		return "", "", &requestError{
			status:  http.StatusBadRequest,
			code:    "invalid_multipart",
			message: "invalid multipart request",
		}
	}

	var (
		tempPath         string
		originalFilename string
	)

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", &requestError{
				status:  http.StatusBadRequest,
				code:    "invalid_multipart",
				message: "failed to read multipart request",
			}
		}

		if part.FormName() != "file" {
			continue
		}

		filename := filepath.Base(strings.TrimSpace(part.FileName()))
		if filename == "" {
			return "", "", &requestError{
				status:  http.StatusBadRequest,
				code:    "missing_filename",
				message: "uploaded file must have a filename",
			}
		}

		tempFile, err := os.CreateTemp("", "callquality-upload-*.pcap")
		if err != nil {
			return "", "", fmt.Errorf("create temporary upload: %w", err)
		}

		tempPath = tempFile.Name()
		originalFilename = filename

		written, copyErr := io.Copy(
			tempFile,
			io.LimitReader(part, maxBytes+1),
		)

		closeErr := tempFile.Close()

		if copyErr != nil {
			os.Remove(tempPath)
			return "", "", fmt.Errorf("write uploaded file: %w", copyErr)
		}

		if closeErr != nil {
			os.Remove(tempPath)
			return "", "", fmt.Errorf("close uploaded file: %w", closeErr)
		}

		if written > maxBytes {
			os.Remove(tempPath)
			return "", "", &requestError{
				status: http.StatusRequestEntityTooLarge,
				code:   "upload_too_large",
				message: fmt.Sprintf(
					"uploaded file exceeds the %d byte limit",
					maxBytes,
				),
			}
		}

		break
	}

	if tempPath == "" {
		return "", "", &requestError{
			status:  http.StatusBadRequest,
			code:    "missing_file",
			message: `multipart field "file" is required`,
		}
	}

	if filepath.Ext(originalFilename) != ".pcap" {
		// The current PCAP reader handles classic PCAP captures only.
		os.Remove(tempPath)
		return "", "", &requestError{
			status:  http.StatusBadRequest,
			code:    "unsupported_capture",
			message: "only .pcap uploads are supported",
		}
	}

	return tempPath, originalFilename, nil
}

type requestError struct {
	status  int
	code    string
	message string
}

func (err *requestError) Error() string {
	return err.message
}

func writeMethodNotAllowed(writer http.ResponseWriter) {
	writer.Header().Set("Allow", "GET, POST, OPTIONS")
	writeError(
		writer,
		http.StatusMethodNotAllowed,
		"method_not_allowed",
		"HTTP method is not supported for this endpoint",
	)
}

func writeError(
	writer http.ResponseWriter,
	status int,
	code string,
	message string,
) {
	writeJSON(writer, status, errorResponse{
		Error: APIError{
			Code:    code,
			Message: message,
		},
	})
}

func writeJSON(
	writer http.ResponseWriter,
	status int,
	value any,
) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")

	_ = encoder.Encode(value)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		writer.Header().Set(
			"Access-Control-Allow-Headers",
			"Content-Type",
		)

		if request.Method == http.MethodOptions {
			writer.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(writer, request)
	})
}

func buildAnalyzeResponse(
	filename string,
	result pipeline.Result,
) analyzeResponse {
	callResponses := make([]callResponse, 0, len(result.CallResults))
	predictionIndex := 0
	recordsByStreamID := make(map[string]export.Record, len(result.Records))

	for _, record := range result.Records {
		recordsByStreamID[record.StreamID] = record
	}

	for _, callAnalysisResult := range result.CallResults {
		callResponse := callResponse{
			CallID:              callAnalysisResult.CallID,
			State:               fmt.Sprintf("%v", callAnalysisResult.State),
			SetupDurationMs:     callAnalysisResult.SetupDurationMs,
			CallDurationMs:      callAnalysisResult.CallDurationMs,
			FinalResponseCode:   callAnalysisResult.FinalResponseCode,
			StreamCount:         callAnalysisResult.StreamCount,
			AnalyzedStreamCount: callAnalysisResult.AnalyzedStreamCount,
			OverallLevel:        string(callAnalysisResult.OverallLevel),
			Streams:             make([]streamResponse, 0, len(callAnalysisResult.Streams)),
		}

		if callAnalysisResult.AnalyzedStreamCount > 0 {
			callResponse.AverageScore = floatPointer(callAnalysisResult.AverageScore)
			callResponse.OverallScore = floatPointer(callAnalysisResult.OverallScore)
		}
		if callAnalysisResult.EModelAvailable {
			callResponse.AverageRFactor = floatPointer(callAnalysisResult.AverageRFactor)
			callResponse.AverageMOS = floatPointer(callAnalysisResult.AverageMOS)
		}
		if callAnalysisResult.PrimaryFinding != "" {
			callResponse.PrimaryDiagnosis = string(callAnalysisResult.PrimaryFinding)
			callResponse.PrimaryDiagnosisSSRC = uint32Pointer(callAnalysisResult.PrimaryFindingSSRC)
		}

		for _, stream := range callAnalysisResult.Streams {
			streamID := exportStreamID(stream.Key, stream.PayloadType)
			record := recordsByStreamID[streamID]

			prediction := ml.Prediction{}
			if predictionIndex < len(result.Predictions) {
				prediction = result.Predictions[predictionIndex]
				predictionIndex++
			}

			callResponse.Streams = append(
				callResponse.Streams,
				buildStreamResponse(record, stream, prediction),
			)
		}

		callResponses = append(callResponses, callResponse)
	}

	return analyzeResponse{
		SchemaVersion: export.SchemaVersion,
		Source: sourceResponse{
			Filename: filename,
		},
		Capture: captureResponse{
			PacketsAnalyzed:    len(result.Packets),
			SIPPackets:         result.Summary.SIPPackets,
			SIPRequests:        result.Summary.SIPRequests,
			SIPResponses:       result.Summary.SIPResponses,
			CallsReconstructed: len(result.Calls),
			RTCPStreams:        len(result.RTCPResults),
		},
		Calls: callResponses,
	}
}

func buildStreamResponse(
	record export.Record,
	stream callanalysis.StreamAnalysis,
	prediction ml.Prediction,
) streamResponse {
	return streamResponse{
		SSRC:           record.SSRC,
		MediaIndex:     record.MediaIndex,
		StreamID:       record.StreamID,
		PayloadType:    record.PayloadType,
		Codec:          record.Codec,
		ClockRate:      record.ClockRate,
		CodecChannels:  record.CodecChannels,
		MediaDirection: record.Direction,
		RTP: rtpResponse{
			PacketCount:       record.PacketCount,
			UniquePackets:     record.UniquePackets,
			DuplicatePackets:  record.DuplicatePackets,
			OutOfOrderPackets: record.OutOfOrderPackets,
			ExpectedPackets:   record.ExpectedPackets,
			LostPackets:       record.LostPackets,
			LossPercent:       record.LossPercent,
			JitterMs:          record.RTPJitterMs,
		},
		RTCP: rtcpResponse{
			Available:           record.RTCPAvailable,
			ObservationCount:    record.RTCPObservationCount,
			LatestLossPercent:   record.LatestFractionLostPercent,
			AverageLossPercent:  record.AverageFractionLostPercent,
			LatestJitterMs:      record.LatestJitterMs,
			AverageJitterMs:     record.AverageJitterMs,
			LatestPassiveRTTMs:  record.LatestPassiveRTTMs,
			AveragePassiveRTTMs: record.AveragePassiveRTTMs,
		},
		Quality: qualityResponse{
			Available:     stream.Quality.Available,
			Score:         pointerIfQualityAvailable(stream.Quality),
			Level:         string(stream.Quality.Level),
			PrimaryFactor: string(stream.Quality.PrimaryFactor),
			Effective: qualityEffectiveResponse{
				LossPercent:       stream.Quality.Effective.LossPercent,
				LossSource:        stream.Quality.Effective.LossSource,
				JitterMs:          stream.Quality.Effective.JitterMs,
				JitterSource:      stream.Quality.Effective.JitterSource,
				RTTMs:             stream.Quality.Effective.RTTMs,
				RTTSource:         stream.Quality.Effective.RTTSource,
				OutOfOrderPercent: stream.Quality.Effective.OutOfOrderPercent,
				DuplicatePercent:  stream.Quality.Effective.DuplicatePercent,
			},
			Factors: buildQualityFactors(stream.Quality.Factors),
		},
		EModel:    buildEModelResponse(stream),
		Diagnosis: buildDiagnosisResponse(stream.Diagnosis),
		ML:        buildMLResponse(prediction),
	}
}

func buildQualityFactors(factors []quality.QualityFactor) []qualityFactorResponse {
	result := make([]qualityFactorResponse, 0, len(factors))

	for _, factor := range factors {
		result = append(result, qualityFactorResponse{
			Name:      string(factor.Name),
			Value:     factor.Value,
			Unit:      factor.Unit,
			Penalty:   factor.Penalty,
			Available: factor.Available,
		})
	}

	return result
}

func buildEModelResponse(stream callanalysis.StreamAnalysis) emodelResponse {
	result := emodelResponse{
		Available: stream.EModelAvailable,
	}

	if !stream.EModelAvailable {
		return result
	}

	result.ModelVersion = stream.EModel.ModelVersion
	result.RFactor = floatPointer(stream.EModel.RFactor)
	result.MOS = floatPointer(stream.EModel.MOSCQE)
	result.OneWayDelayMs = floatPointer(stream.EModel.OneWayDelayMs)
	result.PacketLossPercent = floatPointer(stream.EModel.PacketLossPercent)
	result.DelaySource = stream.EModel.DelaySource
	result.LossSource = stream.EModel.LossSource

	return result
}

func buildDiagnosisResponse(result diagnosis.Result) diagnosisResponse {
	response := diagnosisResponse{
		Available:      result.PrimaryFinding != "",
		PrimaryFinding: string(result.PrimaryFinding),
		QualityLevel:   string(result.QualityLevel),
		QualityScore:   floatPointer(result.QualityScore),
		Findings:       make([]findingResponse, 0, len(result.Findings)),
	}

	for _, finding := range result.Findings {
		response.Findings = append(response.Findings, findingResponse{
			Code:        string(finding.Code),
			Severity:    string(finding.Severity),
			Title:       finding.Title,
			Description: finding.Description,
			Value:       finding.Value,
			Unit:        finding.Unit,
			Threshold:   finding.Threshold,
			Available:   finding.Available,
			Confidence:  finding.Confidence,
		})
	}

	return response
}

func buildMLResponse(prediction ml.Prediction) mlResponse {
	probabilities := make([]mlProbabilityResponse, 0, len(prediction.ClassProbabilities))

	for _, probability := range prediction.ClassProbabilities {
		probabilities = append(probabilities, mlProbabilityResponse{
			Class: probability.Class,
			Value: probability.Value,
		})
	}

	return mlResponse{
		ModelVersion:   ml.ModelArtifactVersion,
		PredictedClass: prediction.PredictedClass,
		MaxClassVote:   prediction.MaxProbability,
		Probabilities:  probabilities,
	}
}

func pointerIfQualityAvailable(assessment quality.StreamAssessment) *float64 {
	if !assessment.Available {
		return nil
	}

	return floatPointer(assessment.Score)
}

func exportStreamID(key rtp.StreamKey, payloadType uint8) string {
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

func floatPointer(value float64) *float64 {
	return &value
}

func uint32Pointer(value uint32) *uint32 {
	return &value
}
