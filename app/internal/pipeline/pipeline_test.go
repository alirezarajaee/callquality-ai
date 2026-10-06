package pipeline

import (
	"path/filepath"
	"testing"
)

func TestAnalyzeFileReturnsIntegratedResult(t *testing.T) {
	service, err := NewService()
	if err != nil {
		t.Fatalf("create service: %v", err)
	}

	path := filepath.Join(
		"..",
		"..",
		"..",
		"samples",
		"synthetic-call.pcap",
	)

	result, err := service.AnalyzeFile(path)
	if err != nil {
		t.Fatalf("analyze file: %v", err)
	}

	if len(result.Packets) != 108 {
		t.Fatalf("packet count mismatch: got %d want 108", len(result.Packets))
	}

	if len(result.Calls) != 1 {
		t.Fatalf("call count mismatch: got %d want 1", len(result.Calls))
	}

	if len(result.CallResults) != 1 {
		t.Fatalf("call result count mismatch: got %d want 1", len(result.CallResults))
	}

	if len(result.Records) != 2 {
		t.Fatalf("record count mismatch: got %d want 2", len(result.Records))
	}

	if len(result.Predictions) != 2 {
		t.Fatalf("prediction count mismatch: got %d want 2", len(result.Predictions))
	}
}
