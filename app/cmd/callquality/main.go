package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alirezarajaee/callquality-ai/app/internal/analyzer"
	"github.com/alirezarajaee/callquality-ai/app/internal/callanalysis"
	"github.com/alirezarajaee/callquality-ai/app/internal/export"
	"github.com/alirezarajaee/callquality-ai/app/internal/ml"
)

const (
	appName    = "CallQuality AI"
	appVersion = "0.1.0"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) error {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}

	switch args[0] {
	case "analyze":
		if len(args) != 2 {
			printAnalyzeUsage(stderr)
			return fmt.Errorf(
				"analyze requires exactly one PCAP file",
			)
		}

		return analyzeFile(
			args[1],
			stdout,
		)

	case "export":
		options, err := parseExportArgs(args[1:])
		if err != nil {
			printExportUsage(stderr)
			return err
		}

		return exportFile(
			options,
			stdout,
		)

	case "predict":
		if len(args) != 2 {
			printPredictUsage(stderr)
			return fmt.Errorf(
				"predict requires exactly one PCAP file",
			)
		}

		return predictFile(
			args[1],
			stdout,
		)

	case "version":
		fmt.Fprintf(
			stdout,
			"%s %s\n",
			appName,
			appVersion,
		)
		return nil

	case "help":
		printUsage(stdout)
		return nil

	default:
		printUsage(stderr)
		return fmt.Errorf(
			"unknown command %q",
			args[0],
		)
	}
}

func analyzeFile(
	path string,
	output io.Writer,
) error {
	summary, packets, calls, rtcpResults, callResults, err :=
		analyzeCapture(path)
	if err != nil {
		return fmt.Errorf(
			"analyze capture: %w",
			err,
		)
	}

	printReport(
		output,
		path,
		summary,
		packets,
		calls,
		rtcpResults,
		callResults,
	)

	model, err := ml.LoadEmbedded()
	if err != nil {
		return fmt.Errorf(
			"load ML model for integrated analysis: %w",
			err,
		)
	}

	records := export.BuildRecords(
		calls,
		callResults,
	)

	return printMLPredictions(
		output,
		model,
		records,
	)
}

func predictFile(
	path string,
	output io.Writer,
) error {
	model, err := ml.LoadEmbedded()
	if err != nil {
		return fmt.Errorf(
			"load ML model: %w",
			err,
		)
	}

	_, _, calls, _, callResults, err := analyzeCapture(path)
	if err != nil {
		return fmt.Errorf(
			"analyze capture for prediction: %w",
			err,
		)
	}

	records := export.BuildRecords(
		calls,
		callResults,
	)

	return printMLPredictions(
		output,
		model,
		records,
	)
}

func printMLPredictions(
	output io.Writer,
	model *ml.Model,
	records []export.Record,
) error {
	if model == nil {
		return fmt.Errorf("ML model is nil")
	}

	if len(records) == 0 {
		fmt.Fprintln(
			output,
			"No media-stream records available for ML prediction.",
		)
		return nil
	}

	fmt.Fprintln(output, "")
	fmt.Fprintln(output, "========================================")
	fmt.Fprintln(output, appName)
	fmt.Fprintln(output, "ML PREDICTIONS")
	fmt.Fprintln(output, "----------------------------------------")
	fmt.Fprintf(
		output,
		"Model: Random Forest (%s)\n",
		ml.ModelArtifactVersion,
	)
	fmt.Fprintln(output, "Runtime: native Go inference")
	fmt.Fprintln(
		output,
		"Probability type: uncalibrated class-vote probability",
	)
	fmt.Fprintln(output, "----------------------------------------")

	for index, record := range records {
		prediction, err := model.PredictRecord(record)
		if err != nil {
			return fmt.Errorf(
				"predict record %d: %w",
				index+1,
				err,
			)
		}

		fmt.Fprintf(
			output,
			"[%d] %s\n",
			index+1,
			record.CallID,
		)
		fmt.Fprintf(
			output,
			"    Media index:  %d\n",
			record.MediaIndex,
		)
		fmt.Fprintf(
			output,
			"    SSRC:         %d\n",
			record.SSRC,
		)
		fmt.Fprintf(
			output,
			"    Codec:        %s\n",
			record.Codec,
		)

		if record.QualityScore != nil {
			fmt.Fprintf(
				output,
				"    Engineering:  %.2f / 100 (%s)\n",
				*record.QualityScore,
				record.QualityLevel,
			)
		} else {
			fmt.Fprintln(
				output,
				"    Engineering:  unavailable",
			)
		}

		if record.DiagnosisPrimary != "" {
			fmt.Fprintf(
				output,
				"    Diagnosis:    %s\n",
				record.DiagnosisPrimary,
			)
		} else {
			fmt.Fprintln(
				output,
				"    Diagnosis:    none",
			)
		}

		fmt.Fprintf(
			output,
			"    ML predicted: %s\n",
			prediction.PredictedClass,
		)
		fmt.Fprintf(
			output,
			"    Max class vote: %.2f%%\n",
			prediction.MaxProbability*100,
		)

		for _, probability := range prediction.ClassProbabilities {
			fmt.Fprintf(
				output,
				"      %-8s %.2f%%\n",
				probability.Class+":",
				probability.Value*100,
			)
		}

		fmt.Fprintln(output, "")
	}

	fmt.Fprintln(output, "========================================")
	return nil
}

func analyzeCapture(
	path string,
) (
	analyzer.AnalysisSummary,
	[]analyzer.AnalyzedPacket,
	[]analyzer.Call,
	[]analyzer.RTCPStreamResult,
	[]callanalysis.CallAnalysis,
	error,
) {
	summary, packets, err := analyzer.AnalyzeFile(path)
	if err != nil {
		return analyzer.AnalysisSummary{}, nil, nil, nil, nil, err
	}

	calls := analyzer.ReconstructCalls(packets)
	calls = analyzer.AttachRTPStreams(calls, packets)

	rtcpResults := analyzer.CorrelateRTCPWithRTPStreams(calls, packets)
	mediaMetrics := analyzer.BuildUnifiedMediaMetrics(calls, rtcpResults)
	callResults := callanalysis.AnalyzeCalls(calls, mediaMetrics)

	return summary, packets, calls, rtcpResults, callResults, nil
}

type exportOptions struct {
	capture string
	format  string
	output  string
}

func parseExportArgs(args []string) (exportOptions, error) {
	if len(args) == 0 {
		return exportOptions{}, fmt.Errorf(
			"export requires a PCAP file",
		)
	}

	options := exportOptions{
		capture: args[0],
		format:  "csv",
	}

	for index := 1; index < len(args); index++ {
		arg := args[index]

		switch {
		case arg == "--format":
			if index+1 >= len(args) {
				return exportOptions{}, fmt.Errorf(
					"--format requires a value",
				)
			}
			index++
			options.format = strings.ToLower(
				strings.TrimSpace(args[index]),
			)

		case strings.HasPrefix(arg, "--format="):
			options.format = strings.ToLower(
				strings.TrimSpace(strings.TrimPrefix(arg, "--format=")),
			)

		case arg == "--output":
			if index+1 >= len(args) {
				return exportOptions{}, fmt.Errorf(
					"--output requires a path",
				)
			}
			index++
			options.output = strings.TrimSpace(args[index])

		case strings.HasPrefix(arg, "--output="):
			options.output = strings.TrimSpace(
				strings.TrimPrefix(arg, "--output="),
			)

		default:
			return exportOptions{}, fmt.Errorf(
				"unknown export option %q",
				arg,
			)
		}
	}

	if options.capture == "" {
		return exportOptions{}, fmt.Errorf(
			"PCAP file path cannot be empty",
		)
	}

	if options.output == "" {
		return exportOptions{}, fmt.Errorf(
			"--output is required",
		)
	}

	switch options.format {
	case "csv", "json":
		return options, nil
	default:
		return exportOptions{}, fmt.Errorf(
			"unsupported export format %q; expected csv or json",
			options.format,
		)
	}
}

func exportFile(
	options exportOptions,
	output io.Writer,
) error {
	_, _, calls, _, callResults, err := analyzeCapture(options.capture)
	if err != nil {
		return fmt.Errorf(
			"analyze capture for export: %w",
			err,
		)
	}

	records := export.BuildRecords(calls, callResults)

	outputPath := filepath.Clean(options.output)
	if dir := filepath.Dir(outputPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf(
				"create export directory: %w",
				err,
			)
		}
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf(
			"create export file: %w",
			err,
		)
	}
	defer file.Close()

	source := export.Source{
		Capture:     options.capture,
		ToolVersion: appVersion,
	}

	switch options.format {
	case "csv":
		err = export.WriteCSV(file, records)
	case "json":
		err = export.WriteJSON(file, source, records)
	}

	if err != nil {
		return fmt.Errorf(
			"write %s export: %w",
			options.format,
			err,
		)
	}

	fmt.Fprintf(
		output,
		"Exported %d media-stream records to %s (%s)\n",
		len(records),
		outputPath,
		options.format,
	)

	return nil
}

func printReport(
	output io.Writer,
	path string,
	summary analyzer.AnalysisSummary,
	packets []analyzer.AnalyzedPacket,
	calls []analyzer.Call,
	rtcpResults []analyzer.RTCPStreamResult,
	callResults []callanalysis.CallAnalysis,
) {
	fmt.Fprintln(
		output,
		"",
	)

	fmt.Fprintln(
		output,
		"========================================",
	)

	fmt.Fprintln(
		output,
		appName,
	)

	fmt.Fprintf(
		output,
		"Version: %s\n",
		appVersion,
	)

	fmt.Fprintln(
		output,
		"========================================",
	)

	fmt.Fprintf(
		output,
		"Capture: %s\n",
		path,
	)

	fmt.Fprintln(
		output,
		"----------------------------------------",
	)

	fmt.Fprintf(
		output,
		"Packets analyzed: %d\n",
		len(packets),
	)

	fmt.Fprintf(
		output,
		"SIP packets:      %d\n",
		summary.SIPPackets,
	)

	fmt.Fprintf(
		output,
		"SIP requests:     %d\n",
		summary.SIPRequests,
	)

	fmt.Fprintf(
		output,
		"SIP responses:    %d\n",
		summary.SIPResponses,
	)

	fmt.Fprintf(
		output,
		"Calls reconstructed: %d\n",
		len(calls),
	)

	fmt.Fprintf(
		output,
		"RTCP streams: %d\n",
		len(rtcpResults),
	)

	fmt.Fprintln(
		output,
		"",
	)

	printCallSummary(
		output,
		callResults,
	)

	fmt.Fprintln(
		output,
		"========================================",
	)
}

func printCallSummary(
	output io.Writer,
	results []callanalysis.CallAnalysis,
) {
	if len(results) == 0 {
		fmt.Fprintln(
			output,
			"No reconstructed calls found.",
		)
		return
	}

	analyzedCount := 0
	eModelCount := 0

	scoreSum := 0.0
	mosSum := 0.0

	var (
		worstCallID string
		worstScore  float64
		worstSet    bool
	)

	stateCounts := make(
		map[string]int,
	)

	for _, result := range results {
		state := fmt.Sprintf(
			"%v",
			result.State,
		)

		stateCounts[state]++

		if result.AnalyzedStreamCount > 0 {
			analyzedCount++

			scoreSum += result.OverallScore

			if !worstSet ||
				result.OverallScore < worstScore {

				worstSet = true
				worstScore = result.OverallScore
				worstCallID = result.CallID
			}
		}

		if result.EModelAvailable {
			eModelCount++
			mosSum += result.AverageMOS
		}
	}

	fmt.Fprintln(
		output,
		"CALL SUMMARY",
	)

	fmt.Fprintln(
		output,
		"----------------------------------------",
	)

	fmt.Fprintf(
		output,
		"Total calls:       %d\n",
		len(results),
	)

	fmt.Fprintf(
		output,
		"Media-analyzed:    %d\n",
		analyzedCount,
	)

	fmt.Fprintf(
		output,
		"E-model available: %d\n",
		eModelCount,
	)

	if analyzedCount > 0 {
		fmt.Fprintf(
			output,
			"Average score:     %.2f / 100\n",
			scoreSum/float64(analyzedCount),
		)
	} else {
		fmt.Fprintln(
			output,
			"Average score:     unavailable",
		)
	}

	if eModelCount > 0 {
		fmt.Fprintf(
			output,
			"Average MOS:       %.3f\n",
			mosSum/float64(eModelCount),
		)
	} else {
		fmt.Fprintln(
			output,
			"Average MOS:       unavailable",
		)
	}

	if worstSet {
		fmt.Fprintf(
			output,
			"Worst call:        %s (%.2f / 100)\n",
			worstCallID,
			worstScore,
		)
	} else {
		fmt.Fprintln(
			output,
			"Worst call:        unavailable",
		)
	}

	fmt.Fprintln(
		output,
		"",
	)

	printStateSummary(
		output,
		stateCounts,
	)

	fmt.Fprintln(
		output,
		"",
	)

	printCallDetails(
		output,
		results,
	)
}

func printStateSummary(
	output io.Writer,
	states map[string]int,
) {
	fmt.Fprintln(
		output,
		"CALL STATES",
	)

	fmt.Fprintln(
		output,
		"----------------------------------------",
	)

	keys := make(
		[]string,
		0,
		len(states),
	)

	for state := range states {
		keys = append(
			keys,
			state,
		)
	}

	sort.Strings(keys)

	for _, state := range keys {
		fmt.Fprintf(
			output,
			"%-16s %d\n",
			state,
			states[state],
		)
	}
}

func printCallDetails(
	output io.Writer,
	results []callanalysis.CallAnalysis,
) {
	fmt.Fprintln(
		output,
		"CALL DETAILS",
	)

	fmt.Fprintln(
		output,
		"----------------------------------------",
	)

	for index, result := range results {
		fmt.Fprintf(
			output,
			"[%d] %s\n",
			index+1,
			result.CallID,
		)

		fmt.Fprintf(
			output,
			"    State:       %v\n",
			result.State,
		)

		fmt.Fprintf(
			output,
			"    Streams:     %d\n",
			result.StreamCount,
		)

		fmt.Fprintf(
			output,
			"    Score:       %.2f\n",
			result.OverallScore,
		)

		fmt.Fprintf(
			output,
			"    Quality:     %s\n",
			result.OverallLevel,
		)

		if result.EModelAvailable {
			fmt.Fprintf(
				output,
				"    MOS:         %.3f\n",
				result.AverageMOS,
			)
		} else {
			fmt.Fprintln(
				output,
				"    MOS:         unavailable",
			)
		}

		if result.PrimaryFinding != "" {
			fmt.Fprintf(
				output,
				"    Diagnosis:   %s\n",
				result.PrimaryFinding,
			)
		} else {
			fmt.Fprintln(
				output,
				"    Diagnosis:   none",
			)
		}

		fmt.Fprintln(
			output,
			"",
		)
	}
}

func printUsage(
	output io.Writer,
) {
	fmt.Fprintln(
		output,
		"CallQuality AI",
	)

	fmt.Fprintln(
		output,
		"",
	)

	fmt.Fprintln(
		output,
		"Usage:",
	)

	fmt.Fprintln(
		output,
		"  callquality analyze <capture.pcap>",
	)

	fmt.Fprintln(
		output,
		"  callquality export <capture.pcap> --format csv --output features.csv",
	)

	fmt.Fprintln(
		output,
		"  callquality export <capture.pcap> --format json --output features.json",
	)

	fmt.Fprintln(
		output,
		"  callquality predict <capture.pcap>",
	)

	fmt.Fprintln(
		output,
		"  callquality version",
	)

	fmt.Fprintln(
		output,
		"  callquality help",
	)
}

func printAnalyzeUsage(
	output io.Writer,
) {
	fmt.Fprintln(
		output,
		"Usage: callquality analyze <capture.pcap>",
	)
}

func printExportUsage(
	output io.Writer,
) {
	fmt.Fprintln(
		output,
		"Usage: callquality export <capture.pcap> --format <csv|json> --output <path>",
	)
	fmt.Fprintln(
		output,
		"Default format: csv",
	)
}

func printPredictUsage(
	output io.Writer,
) {
	fmt.Fprintln(
		output,
		"Usage: callquality predict <capture.pcap>",
	)
	fmt.Fprintln(
		output,
		"Uses the embedded CallQuality AI Random Forest model.",
	)
}
