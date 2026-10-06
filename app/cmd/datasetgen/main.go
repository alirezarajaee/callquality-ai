package main

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/alirezarajaee/callquality-ai/app/internal/analyzer"
	"github.com/alirezarajaee/callquality-ai/app/internal/callanalysis"
	"github.com/alirezarajaee/callquality-ai/app/internal/export"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtcp"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
)

const (
	defaultInput                    = "../samples/synthetic-call.pcap"
	defaultOutputDir                = "../samples/synthetic-dataset"
	defaultSamplesPerScenario       = 5
	defaultProfile                  = "legacy"
	defaultSeed               int64 = 20261001
)

type scenario struct {
	Name        string
	Description string
}

var scenarios = []scenario{
	{Name: "clean", Description: "baseline capture without added impairment"},
	{Name: "loss", Description: "controlled RTP packet loss"},
	{Name: "jitter", Description: "controlled RTP inter-arrival jitter"},
	{Name: "latency", Description: "controlled passive RTCP RTT increase"},
	{Name: "reorder", Description: "controlled RTP packet reordering"},
	{Name: "duplicate", Description: "controlled RTP packet duplication"},
	{Name: "combined", Description: "loss + jitter + passive RTT impairment"},
}

type rawPacket struct {
	Timestamp time.Time
	Data      []byte
}

type rtpInfo struct {
	Index           int
	Sequence        uint16
	SSRC            uint32
	SourceIP        string
	DestinationIP   string
	SourcePort      uint16
	DestinationPort uint16
}

type datasetRow struct {
	SampleID           string
	Scenario           string
	TargetQualityLevel string
	ExportColumns      []string
	ExportValues       []string
}

type datasetWriter struct {
	writer  *csv.Writer
	header  []string
	started bool
}

func main() {
	input := flag.String("input", defaultInput, "baseline synthetic PCAP")
	outputDir := flag.String("output-dir", defaultOutputDir, "directory for generated dataset")
	samplesPerScenario := flag.Int("samples-per-scenario", defaultSamplesPerScenario, "number of samples per scenario")
	profile := flag.String("profile", defaultProfile, "dataset profile: legacy or v4")
	seed := flag.Int64("seed", defaultSeed, "deterministic random seed")
	flag.Parse()

	if *samplesPerScenario <= 0 {
		fatal("samples-per-scenario must be greater than zero")
	}

	if *profile != "legacy" && *profile != "v4" {
		fatal("profile must be either legacy or v4")
	}

	if err := generateDataset(*input, *outputDir, *samplesPerScenario, *seed, *profile); err != nil {
		fatal(err.Error())
	}
}

func generateDataset(inputPath, outputDir string, samplesPerScenario int, seed int64, profile string) error {
	baseline, linkType, snapLen, err := readCapture(inputPath)
	if err != nil {
		return fmt.Errorf("read baseline capture: %w", err)
	}
	if len(baseline) == 0 {
		return fmt.Errorf("baseline capture contains no packets")
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	csvPath := filepath.Join(outputDir, "dataset.csv")
	csvFile, err := os.Create(csvPath)
	if err != nil {
		return fmt.Errorf("create dataset CSV: %w", err)
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	writer := &datasetWriter{writer: csvWriter}

	manifestPath := filepath.Join(outputDir, "manifest.csv")
	manifestFile, err := os.Create(manifestPath)
	if err != nil {
		return fmt.Errorf("create manifest CSV: %w", err)
	}
	defer manifestFile.Close()
	manifestWriter := csv.NewWriter(manifestFile)

	if err := manifestWriter.Write([]string{
		"sample_id",
		"scenario",
		"description",
		"profile",
		"seed",
		"severity_band",
		"recipe",
		"capture_file",
	}); err != nil {
		return fmt.Errorf("write manifest header: %w", err)
	}

	baseRNG := rand.New(rand.NewSource(seed))
	totalRecords := 0
	totalCaptures := 0

	for _, spec := range scenarios {
		for sampleIndex := 0; sampleIndex < samplesPerScenario; sampleIndex++ {
			sampleSeed := baseRNG.Int63()
			rng := rand.New(rand.NewSource(sampleSeed))

			capture, severityBand, recipe := generateScenarioCapture(
				spec.Name,
				baseline,
				sampleIndex,
				rng,
				profile,
			)

			sampleID := fmt.Sprintf("%s-%03d", spec.Name, sampleIndex+1)
			captureName := sampleID + ".pcap"
			capturePath := filepath.Join(outputDir, captureName)

			if err := writeCapture(capturePath, capture, linkType, snapLen); err != nil {
				return fmt.Errorf("write sample %s: %w", sampleID, err)
			}

			records, err := analyzeCaptureRecords(capturePath)
			if err != nil {
				return fmt.Errorf("analyze sample %s: %w", sampleID, err)
			}

			for _, record := range records {
				if err := writer.Write(sampleID, spec.Name, record); err != nil {
					return fmt.Errorf("append dataset record for %s: %w", sampleID, err)
				}
				totalRecords++
			}

			if err := manifestWriter.Write([]string{
				sampleID,
				spec.Name,
				spec.Description,
				profile,
				strconv.FormatInt(sampleSeed, 10),
				severityBand,
				recipe,
				captureName,
			}); err != nil {
				return fmt.Errorf("write manifest row: %w", err)
			}

			totalCaptures++
		}
	}

	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("flush dataset CSV: %w", err)
	}

	manifestWriter.Flush()
	if err := manifestWriter.Error(); err != nil {
		return fmt.Errorf("flush manifest CSV: %w", err)
	}

	fmt.Printf("Generated synthetic dataset:\n")
	fmt.Printf("  captures: %d\n", totalCaptures)
	fmt.Printf("  media-stream records: %d\n", totalRecords)
	fmt.Printf("  dataset: %s\n", csvPath)
	fmt.Printf("  manifest: %s\n", manifestPath)

	return nil
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "Error:", message)
	os.Exit(1)
}

func readCapture(path string) ([]rawPacket, layers.LinkType, uint32, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, err
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return nil, 0, 0, err
	}

	packets := make([]rawPacket, 0, 128)
	for {
		data, captureInfo, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, 0, 0, err
		}
		packets = append(packets, rawPacket{
			Timestamp: captureInfo.Timestamp,
			Data:      append([]byte(nil), data...),
		})
	}

	return packets, reader.LinkType(), 65535, nil
}

func writeCapture(path string, packets []rawPacket, linkType layers.LinkType, snapLen uint32) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(snapLen, linkType); err != nil {
		return err
	}

	for _, packet := range packets {
		data := packet.Data
		if len(data) > int(snapLen) {
			data = data[:snapLen]
		}
		captureInfo := gopacket.CaptureInfo{
			Timestamp:     packet.Timestamp,
			CaptureLength: len(data),
			Length:        len(data),
		}
		if err := writer.WritePacket(captureInfo, data); err != nil {
			return err
		}
	}

	return nil
}

func cloneCapture(input []rawPacket) []rawPacket {
	result := make([]rawPacket, len(input))
	for i, packet := range input {
		result[i] = rawPacket{
			Timestamp: packet.Timestamp,
			Data:      append([]byte(nil), packet.Data...),
		}
	}
	return result
}

type v4SeverityBand struct {
	Name string

	MinLoss int
	MaxLoss int

	MinJitter time.Duration
	MaxJitter time.Duration

	MinLatency time.Duration
	MaxLatency time.Duration

	MinReorder int
	MaxReorder int

	MinDuplicate int
	MaxDuplicate int
}

var v4SeverityBands = []v4SeverityBand{
	{
		Name:         "mild",
		MinLoss:      0,
		MaxLoss:      2,
		MinJitter:    3 * time.Millisecond,
		MaxJitter:    8 * time.Millisecond,
		MinLatency:   0,
		MaxLatency:   30 * time.Millisecond,
		MinReorder:   1,
		MaxReorder:   2,
		MinDuplicate: 1,
		MaxDuplicate: 2,
	},
	{
		Name:         "moderate",
		MinLoss:      2,
		MaxLoss:      5,
		MinJitter:    8 * time.Millisecond,
		MaxJitter:    18 * time.Millisecond,
		MinLatency:   30 * time.Millisecond,
		MaxLatency:   80 * time.Millisecond,
		MinReorder:   2,
		MaxReorder:   4,
		MinDuplicate: 2,
		MaxDuplicate: 4,
	},
	{
		Name:         "degraded",
		MinLoss:      5,
		MaxLoss:      9,
		MinJitter:    18 * time.Millisecond,
		MaxJitter:    32 * time.Millisecond,
		MinLatency:   70 * time.Millisecond,
		MaxLatency:   150 * time.Millisecond,
		MinReorder:   3,
		MaxReorder:   6,
		MinDuplicate: 3,
		MaxDuplicate: 6,
	},
	{
		Name:         "severe",
		MinLoss:      9,
		MaxLoss:      15,
		MinJitter:    30 * time.Millisecond,
		MaxJitter:    55 * time.Millisecond,
		MinLatency:   140 * time.Millisecond,
		MaxLatency:   260 * time.Millisecond,
		MinReorder:   5,
		MaxReorder:   8,
		MinDuplicate: 5,
		MaxDuplicate: 8,
	},
	{
		Name:         "extreme",
		MinLoss:      14,
		MaxLoss:      20,
		MinJitter:    50 * time.Millisecond,
		MaxJitter:    75 * time.Millisecond,
		MinLatency:   250 * time.Millisecond,
		MaxLatency:   380 * time.Millisecond,
		MinReorder:   6,
		MaxReorder:   10,
		MinDuplicate: 6,
		MaxDuplicate: 10,
	},
}

type v4Recipe struct {
	Primary   string
	Secondary string
	Loss      int
	Jitter    time.Duration
	Latency   time.Duration
	Reorder   int
	Duplicate int
}

func (r v4Recipe) String() string {
	return fmt.Sprintf(
		"primary=%s;secondary=%s;loss=%d;jitter_ms=%d;latency_ms=%d;reorder=%d;duplicate=%d",
		r.Primary,
		r.Secondary,
		r.Loss,
		r.Jitter.Milliseconds(),
		r.Latency.Milliseconds(),
		r.Reorder,
		r.Duplicate,
	)
}

func generateScenarioCapture(
	name string,
	packets []rawPacket,
	sampleIndex int,
	rng *rand.Rand,
	profile string,
) ([]rawPacket, string, string) {
	if profile != "v4" {
		return applyScenarioWithVariableLength(name, packets, sampleIndex, rng), "legacy", "legacy"
	}

	capture, band, recipe := applyV4Scenario(
		name,
		packets,
		sampleIndex,
		rng,
	)

	return capture, band.Name, recipe.String()
}

func applyV4Scenario(
	name string,
	packets []rawPacket,
	sampleIndex int,
	rng *rand.Rand,
) ([]rawPacket, v4SeverityBand, v4Recipe) {
	result := cloneCapture(packets)

	band := v4SeverityBands[sampleIndex%len(v4SeverityBands)]
	recipe := v4Recipe{
		Primary: name,
	}

	if name == "clean" {
		recipe.Secondary = "none"
		return result, band, recipe
	}

	recipe.Secondary = chooseSecondaryImpairment(name, rng)

	switch name {
	case "loss":
		recipe.Loss = randomIntInclusive(rng, band.MinLoss, band.MaxLoss)
		result = applyLoss(result, recipe.Loss, rng)

	case "jitter":
		recipe.Jitter = randomDuration(rng, band.MinJitter, band.MaxJitter)
		applyJitter(result, recipe.Jitter, rng)

	case "latency":
		recipe.Latency = randomDuration(rng, band.MinLatency, band.MaxLatency)
		applyLatency(result, recipe.Latency)

	case "reorder":
		recipe.Reorder = randomIntInclusive(rng, band.MinReorder, band.MaxReorder)
		applyReorder(result, recipe.Reorder)

	case "duplicate":
		recipe.Duplicate = randomIntInclusive(rng, band.MinDuplicate, band.MaxDuplicate)
		result = duplicateCapture(result, recipe.Duplicate, rng)

	case "combined":
		recipe.Loss = randomIntInclusive(rng, band.MinLoss, band.MaxLoss)
		recipe.Jitter = randomDuration(rng, band.MinJitter, band.MaxJitter)
		recipe.Latency = randomDuration(rng, band.MinLatency, band.MaxLatency)

		result = applyLoss(result, recipe.Loss, rng)
		applyJitter(result, recipe.Jitter, rng)
		applyLatency(result, recipe.Latency)

		if band.Name == "severe" || band.Name == "extreme" {
			recipe.Reorder = randomIntInclusive(rng, band.MinReorder, band.MaxReorder)
			applyReorder(result, recipe.Reorder)
		}

		if band.Name == "extreme" {
			recipe.Duplicate = randomIntInclusive(rng, band.MinDuplicate, band.MaxDuplicate)
			result = duplicateCapture(result, recipe.Duplicate, rng)
		}
	}

	applySecondaryImpairment(
		&result,
		recipe.Secondary,
		band,
		rng,
	)

	return result, band, recipe
}

func chooseSecondaryImpairment(
	primary string,
	rng *rand.Rand,
) string {
	options := []string{
		"loss",
		"jitter",
		"latency",
		"reorder",
		"duplicate",
	}

	filtered := make([]string, 0, len(options)-1)
	for _, option := range options {
		if option != primary {
			filtered = append(filtered, option)
		}
	}

	return filtered[rng.Intn(len(filtered))]
}

func applySecondaryImpairment(
	packets *[]rawPacket,
	name string,
	band v4SeverityBand,
	rng *rand.Rand,
) {
	if packets == nil {
		return
	}

	switch name {
	case "loss":
		maximum := minInt(3, maxInt(1, band.MaxLoss/4))
		count := randomIntInclusive(rng, 0, maximum)
		*packets = applyLoss(*packets, count, rng)

	case "jitter":
		maximum := band.MaxJitter / 4
		if maximum < 2*time.Millisecond {
			maximum = 2 * time.Millisecond
		}
		applyJitter(
			*packets,
			randomDuration(
				rng,
				1*time.Millisecond,
				maximum,
			),
			rng,
		)

	case "latency":
		maximum := band.MaxLatency / 4
		applyLatency(
			*packets,
			randomDuration(rng, 0, maximum),
		)

	case "reorder":
		maximum := minInt(3, band.MaxReorder)
		applyReorder(
			*packets,
			randomIntInclusive(rng, 1, maximum),
		)

	case "duplicate":
		maximum := minInt(3, band.MaxDuplicate)
		result := duplicateCapture(
			*packets,
			randomIntInclusive(rng, 1, maximum),
			rng,
		)
		*packets = result
	}
}

func randomIntInclusive(rng *rand.Rand, minimum, maximum int) int {
	if maximum <= minimum {
		return minimum
	}

	return minimum + rng.Intn(maximum-minimum+1)
}

func minInt(left, right int) int {
	if left < right {
		return left
	}

	return right
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}

	return right
}

func applyScenarioWithVariableLength(name string, packets []rawPacket, sampleIndex int, rng *rand.Rand) []rawPacket {
	result := cloneCapture(packets)

	switch name {
	case "clean":
		return result

	case "loss":
		return applyLoss(
			result,
			1+sampleIndex%8,
			rng,
		)

	case "jitter":
		applyJitter(
			result,
			time.Duration(4+sampleIndex%8*2)*time.Millisecond,
			rng,
		)
		return result

	case "latency":
		applyLatency(
			result,
			time.Duration(40+sampleIndex%8*15)*time.Millisecond,
		)
		return result

	case "reorder":
		applyReorder(
			result,
			1+sampleIndex%4,
		)
		return result

	case "duplicate":
		return duplicateCapture(
			result,
			1+sampleIndex%4,
			rng,
		)

	case "combined":
		result = applyLoss(
			result,
			2+sampleIndex%9,
			rng,
		)
		applyJitter(
			result,
			time.Duration(8+sampleIndex%8*2)*time.Millisecond,
			rng,
		)
		applyLatency(
			result,
			time.Duration(80+sampleIndex%7*12)*time.Millisecond,
		)
		return result
	}

	return result
}

func applyLoss(packets []rawPacket, perStream int, rng *rand.Rand) []rawPacket {
	indices := rtpIndices(packets)
	groups := groupRTPIndices(indices)
	toDrop := make(map[int]struct{})

	for _, group := range groups {
		if len(group) <= 5 {
			continue
		}
		count := perStream
		if count >= len(group)-2 {
			count = len(group) - 2
		}
		for _, index := range chooseMiddleIndices(group, count, rng) {
			toDrop[index] = struct{}{}
		}
	}

	result := make([]rawPacket, 0, len(packets)-len(toDrop))
	for index, packet := range packets {
		if _, drop := toDrop[index]; drop {
			continue
		}
		result = append(result, packet)
	}
	return result
}

func applyJitter(packets []rawPacket, amplitude time.Duration, rng *rand.Rand) {
	groups := groupRTPIndices(rtpIndices(packets))
	for _, group := range groups {
		if len(group) < 3 {
			continue
		}

		previous := packets[group[0]].Timestamp
		for position := 1; position < len(group); position++ {
			index := group[position]
			interval := 20*time.Millisecond + randomDuration(rng, -amplitude, amplitude)
			if interval < 2*time.Millisecond {
				interval = 2 * time.Millisecond
			}
			previous = previous.Add(interval)
			packets[index].Timestamp = previous
		}
	}
}

func applyLatency(packets []rawPacket, extra time.Duration) {
	for index := range packets {
		if isRTCPReceiverReport(packets[index].Data) {
			packets[index].Timestamp = packets[index].Timestamp.Add(extra)
		}
	}
}

func applyReorder(packets []rawPacket, swapsPerStream int) {
	groups := groupRTPIndices(rtpIndices(packets))
	for _, group := range groups {
		maxSwaps := (len(group) - 2) / 3
		if maxSwaps < 1 {
			continue
		}
		if swapsPerStream > maxSwaps {
			swapsPerStream = maxSwaps
		}

		for i := 0; i < swapsPerStream; i++ {
			left := 2 + i*3
			if left+1 >= len(group) {
				break
			}
			first := group[left]
			second := group[left+1]
			packets[first].Data, packets[second].Data = packets[second].Data, packets[first].Data
		}
	}
}

func duplicateCapture(packets []rawPacket, perStream int, rng *rand.Rand) []rawPacket {
	groups := groupRTPIndices(rtpIndices(packets))
	positions := make(map[int][]rawPacket)
	for _, group := range groups {
		if len(group) < 5 {
			continue
		}
		count := perStream
		if count > len(group)-2 {
			count = len(group) - 2
		}
		for _, index := range chooseMiddleIndices(group, count, rng) {
			positions[index] = append(positions[index], rawPacket{
				Timestamp: packets[index].Timestamp.Add(time.Millisecond),
				Data:      append([]byte(nil), packets[index].Data...),
			})
		}
	}
	result := make([]rawPacket, 0, len(packets)+len(positions)*2)
	for index, packet := range packets {
		result = append(result, packet)
		result = append(result, positions[index]...)
	}
	return result
}

func rtpIndices(packets []rawPacket) []rtpInfo {
	result := make([]rtpInfo, 0, len(packets))
	for index, packet := range packets {
		decoded := gopacket.NewPacket(packet.Data, layers.LinkTypeEthernet, gopacket.NoCopy)
		udpLayer := decoded.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			continue
		}
		rtpPacket, err := rtp.Parse(udp.Payload)
		if err != nil {
			continue
		}
		result = append(result, rtpInfo{
			Index:           index,
			Sequence:        rtpPacket.SequenceNumber,
			SSRC:            rtpPacket.SSRC,
			SourceIP:        udpNetworkIP(decoded, true),
			DestinationIP:   udpNetworkIP(decoded, false),
			SourcePort:      uint16(udp.SrcPort),
			DestinationPort: uint16(udp.DstPort),
		})
	}
	return result
}

func udpNetworkIP(packet gopacket.Packet, source bool) string {
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip, ok := layer.(*layers.IPv4)
		if ok {
			if source {
				return ip.SrcIP.String()
			}
			return ip.DstIP.String()
		}
	}
	if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		ip, ok := layer.(*layers.IPv6)
		if ok {
			if source {
				return ip.SrcIP.String()
			}
			return ip.DstIP.String()
		}
	}
	return ""
}

func groupRTPIndices(infos []rtpInfo) [][]int {
	groups := make(map[string][]int)
	for _, info := range infos {
		key := fmt.Sprintf("%08x|%s|%d|%s|%d", info.SSRC, info.SourceIP, info.SourcePort, info.DestinationIP, info.DestinationPort)
		groups[key] = append(groups[key], info.Index)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([][]int, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		sort.Ints(group)
		result = append(result, group)
	}
	return result
}

func chooseMiddleIndices(group []int, count int, rng *rand.Rand) []int {
	if count <= 0 || len(group) <= 2 {
		return nil
	}
	available := append([]int(nil), group[1:len(group)-1]...)
	rng.Shuffle(len(available), func(i, j int) {
		available[i], available[j] = available[j], available[i]
	})
	if count > len(available) {
		count = len(available)
	}
	return append([]int(nil), available[:count]...)
}

func randomDuration(rng *rand.Rand, minValue, maxValue time.Duration) time.Duration {
	span := int64(maxValue-minValue) + 1
	if span <= 1 {
		return minValue
	}
	return minValue + time.Duration(rng.Int63n(span))
}

func isRTCPReceiverReport(data []byte) bool {
	return len(data) > 0 && rtcp.Detect(extractUDPPayload(data)).HasReceiverReport
}

func extractUDPPayload(data []byte) []byte {
	packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.NoCopy)
	layer := packet.Layer(layers.LayerTypeUDP)
	if layer == nil {
		return nil
	}
	udp, ok := layer.(*layers.UDP)
	if !ok {
		return nil
	}
	return udp.Payload
}

func analyzeCaptureRecords(path string) ([]export.Record, error) {
	summary, packets, err := analyzer.AnalyzeFile(path)
	if err != nil {
		return nil, err
	}
	_ = summary

	calls := analyzer.ReconstructCalls(packets)
	calls = analyzer.AttachRTPStreams(calls, packets)
	rtcpResults := analyzer.CorrelateRTCPWithRTPStreams(calls, packets)
	mediaMetrics := analyzer.BuildUnifiedMediaMetrics(calls, rtcpResults)
	analyses := callanalysis.AnalyzeCalls(calls, mediaMetrics)
	return export.BuildRecords(calls, analyses), nil
}

func (w *datasetWriter) Write(sampleID, scenarioName string, record export.Record) error {
	var buffer bytes.Buffer
	if err := export.WriteCSV(&buffer, []export.Record{record}); err != nil {
		return err
	}

	rows, err := csv.NewReader(strings.NewReader(buffer.String())).ReadAll()
	if err != nil {
		return err
	}
	if len(rows) != 2 {
		return fmt.Errorf("unexpected exported CSV row count: %d", len(rows))
	}

	if !w.started {
		w.header = append([]string{"sample_id", "scenario", "target_quality_level"}, rows[0]...)
		if err := w.writer.Write(w.header); err != nil {
			return err
		}
		w.started = true
	}

	row := append([]string{
		sampleID,
		scenarioName,
		record.QualityLevel,
	}, rows[1]...)
	return w.writer.Write(row)
}
