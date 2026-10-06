package pcap

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
)

type PacketInfo struct {
	Number      int
	Timestamp   time.Time
	CapturedLen int
	OriginalLen int
}

type CaptureSummary struct {
	FilePath       string
	PacketCount    int
	FirstTimestamp time.Time
	LastTimestamp  time.Time
	Duration       time.Duration
	LinkType       string
}

func ReadFile(path string) (CaptureSummary, []PacketInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return CaptureSummary{}, nil, fmt.Errorf("open capture: %w", err)
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return CaptureSummary{}, nil, fmt.Errorf("create pcap reader: %w", err)
	}

	summary := CaptureSummary{
		FilePath: path,
		LinkType: reader.LinkType().String(),
	}

	var packets []PacketInfo
	packetNumber := 0

	for {
		_, captureInfo, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}

			return CaptureSummary{}, nil, fmt.Errorf(
				"read packet %d: %w",
				packetNumber+1,
				err,
			)
		}

		packetNumber++

		if packetNumber == 1 {
			summary.FirstTimestamp = captureInfo.Timestamp
		}

		summary.LastTimestamp = captureInfo.Timestamp

		packets = append(packets, PacketInfo{
			Number:      packetNumber,
			Timestamp:   captureInfo.Timestamp,
			CapturedLen: captureInfo.CaptureLength,
			OriginalLen: captureInfo.Length,
		})
	}

	summary.PacketCount = packetNumber

	if packetNumber > 0 {
		summary.Duration = summary.LastTimestamp.Sub(summary.FirstTimestamp)
	}

	return summary, packets, nil
}