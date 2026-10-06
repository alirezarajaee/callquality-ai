package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/alirezarajaee/callquality-ai/app/internal/pipeline"
)

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()

	service, err := pipeline.NewService()
	if err != nil {
		t.Fatalf("create analysis service: %v", err)
	}

	handler, err := NewServer(
		service,
		Config{MaxUploadBytes: 8 << 20},
	)
	if err != nil {
		t.Fatalf("create API server: %v", err)
	}

	return handler
}

func TestHealthEndpoint(t *testing.T) {
	handler := newTestHandler(t)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status mismatch: got %d want %d", recorder.Code, http.StatusOK)
	}

	var response healthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode health response: %v", err)
	}

	if response.Status != "ok" {
		t.Fatalf("health status mismatch: got %q", response.Status)
	}
}

func TestVersionEndpoint(t *testing.T) {
	handler := newTestHandler(t)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status mismatch: got %d want %d", recorder.Code, http.StatusOK)
	}

	var response versionResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode version response: %v", err)
	}

	if response.Name != "CallQuality AI" {
		t.Fatalf("name mismatch: got %q", response.Name)
	}

	if response.APIVersion != APIVersion {
		t.Fatalf("API version mismatch: got %q want %q", response.APIVersion, APIVersion)
	}
}

func TestAnalyzeEndpointWithSyntheticCapture(t *testing.T) {
	handler := newTestHandler(t)

	capturePath := filepath.Join(
		"..",
		"..",
		"..",
		"samples",
		"synthetic-call.pcap",
	)

	data, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("read synthetic capture %q: %v", capturePath, err)
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile("file", "synthetic-call.pcap")
	if err != nil {
		t.Fatalf("create multipart part: %v", err)
	}

	if _, err := part.Write(data); err != nil {
		t.Fatalf("write multipart part: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/analyze",
		&body,
	)
	request.Header.Set("Content-Type", writer.FormDataContentType())

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"status mismatch: got %d body=%s",
			recorder.Code,
			recorder.Body.String(),
		)
	}

	var response analyzeResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode analyze response: %v", err)
	}

	if response.Capture.PacketsAnalyzed != 108 {
		t.Fatalf(
			"packet count mismatch: got %d want 108",
			response.Capture.PacketsAnalyzed,
		)
	}

	if len(response.Calls) != 1 {
		t.Fatalf("call count mismatch: got %d want 1", len(response.Calls))
	}

	call := response.Calls[0]

	if call.CallID != "synthetic-call-001@example.com" {
		t.Fatalf("call ID mismatch: got %q", call.CallID)
	}

	if len(call.Streams) != 2 {
		t.Fatalf("stream count mismatch: got %d want 2", len(call.Streams))
	}

	if call.Streams[0].ML.PredictedClass == "" {
		t.Fatal("ML prediction is empty")
	}
}

func TestAnalyzeRejectsMissingFile(t *testing.T) {
	handler := newTestHandler(t)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/analyze",
		&body,
	)
	request.Header.Set("Content-Type", writer.FormDataContentType())

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf(
			"status mismatch: got %d want %d",
			recorder.Code,
			http.StatusBadRequest,
		)
	}

	var response errorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}

	if response.Error.Code != "missing_file" {
		t.Fatalf(
			"error code mismatch: got %q want missing_file",
			response.Error.Code,
		)
	}
}

func TestAnalyzeRejectsNonPCAPFilename(t *testing.T) {
	handler := newTestHandler(t)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile("file", "capture.txt")
	if err != nil {
		t.Fatalf("create multipart part: %v", err)
	}

	if _, err := io.WriteString(part, "not a PCAP"); err != nil {
		t.Fatalf("write multipart part: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/analyze",
		&body,
	)
	request.Header.Set("Content-Type", writer.FormDataContentType())

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf(
			"status mismatch: got %d want %d",
			recorder.Code,
			http.StatusBadRequest,
		)
	}

	var response errorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}

	if response.Error.Code != "unsupported_capture" {
		t.Fatalf(
			"error code mismatch: got %q want unsupported_capture",
			response.Error.Code,
		)
	}
}

func TestCORSPreflight(t *testing.T) {
	handler := newTestHandler(t)

	request := httptest.NewRequest(http.MethodOptions, "/api/v1/analyze", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status mismatch: got %d want %d", recorder.Code, http.StatusNoContent)
	}

	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("CORS origin mismatch: got %q", got)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	handler := newTestHandler(t)

	request := httptest.NewRequest(http.MethodDelete, "/api/v1/health", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf(
			"status mismatch: got %d want %d",
			recorder.Code,
			http.StatusMethodNotAllowed,
		)
	}
}
