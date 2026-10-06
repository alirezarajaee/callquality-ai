package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alirezarajaee/callquality-ai/app/internal/export"
	"github.com/alirezarajaee/callquality-ai/app/internal/ml"
)

func TestRunVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(
		[]string{"version"},
		&stdout,
		&stderr,
	)

	if err != nil {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	output := stdout.String()

	if !strings.Contains(
		output,
		"CallQuality AI",
	) {
		t.Fatalf(
			"expected app name in output: %q",
			output,
		)
	}

	if !strings.Contains(
		output,
		appVersion,
	) {
		t.Fatalf(
			"expected version in output: %q",
			output,
		)
	}

	if stderr.Len() != 0 {
		t.Fatalf(
			"expected empty stderr, got %q",
			stderr.String(),
		)
	}
}

func TestRunHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(
		[]string{"help"},
		&stdout,
		&stderr,
	)

	if err != nil {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	output := stdout.String()

	expectedParts := []string{
		"callquality analyze <capture.pcap>",
		"callquality export <capture.pcap>",
		"callquality version",
		"callquality help",
	}

	for _, part := range expectedParts {
		if !strings.Contains(
			output,
			part,
		) {
			t.Fatalf(
				"expected %q in help output: %q",
				part,
				output,
			)
		}
	}

	if stderr.Len() != 0 {
		t.Fatalf(
			"expected empty stderr, got %q",
			stderr.String(),
		)
	}
}

func TestRunWithoutArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(
		nil,
		&stdout,
		&stderr,
	)

	if err != nil {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	if !strings.Contains(
		stdout.String(),
		"Usage:",
	) {
		t.Fatalf(
			"expected usage output: %q",
			stdout.String(),
		)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(
		[]string{"something"},
		&stdout,
		&stderr,
	)

	if err == nil {
		t.Fatal("expected error for unknown command")
	}

	if !strings.Contains(
		err.Error(),
		"unknown command",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	if !strings.Contains(
		stderr.String(),
		"Usage:",
	) {
		t.Fatalf(
			"expected usage on stderr: %q",
			stderr.String(),
		)
	}
}

func TestRunAnalyzeRequiresPath(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(
		[]string{"analyze"},
		&stdout,
		&stderr,
	)

	if err == nil {
		t.Fatal(
			"expected error when analyze path is missing",
		)
	}

	if !strings.Contains(
		err.Error(),
		"exactly one PCAP file",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	if !strings.Contains(
		stderr.String(),
		"callquality analyze <capture.pcap>",
	) {
		t.Fatalf(
			"expected analyze usage, got %q",
			stderr.String(),
		)
	}
}

func TestRunAnalyzeRejectsTooManyArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(
		[]string{
			"analyze",
			"one.pcap",
			"two.pcap",
		},
		&stdout,
		&stderr,
	)

	if err == nil {
		t.Fatal(
			"expected error for too many arguments",
		)
	}

	if !strings.Contains(
		err.Error(),
		"exactly one PCAP file",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestRunAnalyzeMissingFile(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	missingPath := filepath.Join(
		os.TempDir(),
		"callquality-ai-missing-capture.pcap",
	)

	_ = os.Remove(missingPath)

	err := run(
		[]string{
			"analyze",
			missingPath,
		},
		&stdout,
		&stderr,
	)

	if err == nil {
		t.Fatal(
			"expected error for missing capture",
		)
	}

	if !strings.Contains(
		err.Error(),
		"analyze capture",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestParseExportArgs(t *testing.T) {
	options, err := parseExportArgs([]string{
		"capture.pcap",
		"--format",
		"JSON",
		"--output",
		"features.json",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if options.capture != "capture.pcap" {
		t.Fatalf("capture mismatch: %q", options.capture)
	}
	if options.format != "json" {
		t.Fatalf("format mismatch: %q", options.format)
	}
	if options.output != "features.json" {
		t.Fatalf("output mismatch: %q", options.output)
	}
}

func TestParseExportArgsDefaultsToCSV(t *testing.T) {
	options, err := parseExportArgs([]string{
		"capture.pcap",
		"--output=features.csv",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if options.format != "csv" {
		t.Fatalf("expected csv default, got %q", options.format)
	}
}

func TestParseExportArgsRejectsInvalidFormat(t *testing.T) {
	_, err := parseExportArgs([]string{
		"capture.pcap",
		"--format",
		"xml",
		"--output",
		"features.xml",
	})
	if err == nil {
		t.Fatal("expected invalid format error")
	}
	if !strings.Contains(err.Error(), "unsupported export format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseExportArgsRequiresOutput(t *testing.T) {
	_, err := parseExportArgs([]string{
		"capture.pcap",
	})
	if err == nil {
		t.Fatal("expected missing output error")
	}
	if !strings.Contains(err.Error(), "--output is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunPredictRequiresPath(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(
		[]string{"predict"},
		&stdout,
		&stderr,
	)

	if err == nil {
		t.Fatal("expected error when predict path is missing")
	}

	if !strings.Contains(
		err.Error(),
		"predict requires exactly one PCAP file",
	) {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(
		stderr.String(),
		"callquality predict <capture.pcap>",
	) {
		t.Fatalf("expected predict usage, got %q", stderr.String())
	}
}

func TestRunPredictRejectsTooManyArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run(
		[]string{
			"predict",
			"one.pcap",
			"two.pcap",
		},
		&stdout,
		&stderr,
	)

	if err == nil {
		t.Fatal("expected error for too many predict arguments")
	}

	if !strings.Contains(
		err.Error(),
		"predict requires exactly one PCAP file",
	) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrintMLPredictionsIncludesIntegratedEvidence(t *testing.T) {
	model, err := ml.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded failed: %v", err)
	}

	qualityScore := 87.59
	averageRTT := 150.0
	rtpJitter := 4.44
	rtcpJitter := 4.5
	fractionLost := 0.0
	cumulativeLost := int32(0)

	record := export.Record{
		SchemaVersion:              export.SchemaVersion,
		CallID:                     "synthetic-call-001@example.com",
		MediaIndex:                 0,
		StreamID:                   "11111111:10.10.0.1:10000->10.10.0.2:20000:pt0",
		SSRC:                       0x11111111,
		PayloadType:                0,
		Codec:                      "PCMU",
		ClockRate:                  8000,
		CodecChannels:              1,
		Direction:                  "sendrecv",
		SetupDurationMs:            200,
		CallDurationMs:             1100,
		PacketCount:                50,
		UniquePackets:              50,
		ExpectedPackets:            50,
		LostPackets:                0,
		RTPLossPercent:             0,
		LossPercent:                0,
		RTPLossAvailable:           true,
		RTPJitterMs:                &rtpJitter,
		RTCPAvailable:              true,
		RTCPObservationCount:       1,
		LatestFractionLostPercent:  &fractionLost,
		AverageFractionLostPercent: &fractionLost,
		LatestCumulativeLost:       &cumulativeLost,
		LatestJitterMs:             &rtcpJitter,
		AverageJitterMs:            &rtcpJitter,
		AveragePassiveRTTMs:        &averageRTT,
		LatestPassiveRTTMs:         &averageRTT,
		QualityAvailable:           true,
		QualityScore:               &qualityScore,
		QualityLevel:               "good",
		DiagnosisAvailable:         false,
	}

	var output bytes.Buffer

	if err := printMLPredictions(
		&output,
		model,
		[]export.Record{record},
	); err != nil {
		t.Fatalf("printMLPredictions failed: %v", err)
	}

	result := output.String()

	expectedParts := []string{
		"ML PREDICTIONS",
		"Engineering:  87.59 / 100 (good)",
		"Diagnosis:    none",
		"ML predicted: good",
		"critical:",
		"fair:",
		"good:",
		"poor:",
	}

	for _, part := range expectedParts {
		if !strings.Contains(result, part) {
			t.Fatalf(
				"expected %q in integrated ML output: %q",
				part,
				result,
			)
		}
	}
}
