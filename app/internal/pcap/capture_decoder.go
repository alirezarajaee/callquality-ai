package pcap

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
)

type DecodedCapturePacket struct {
	Number        int
	Timestamp     time.Time
	CapturedLen   int
	OriginalLen   int
	DecodedPacket DecodedPacket
}

type DecodedCaptureSummary struct {
	FilePath       string
	PacketCount    int
	FirstTimestamp time.Time
	LastTimestamp  time.Time
	Duration       time.Duration
	LinkType       string
	IPv4Packets    int
	IPv6Packets    int
	TCPPackets     int
	UDPPackets     int
}

func ReadAndDecodeFile(
	path string,
) (DecodedCaptureSummary, []DecodedCapturePacket, error) {
	file, err := os.Open(path)
	if err != nil {
		return DecodedCaptureSummary{}, nil,
			fmt.Errorf("open capture: %w", err)
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return DecodedCaptureSummary{}, nil,
			fmt.Errorf("create pcap reader: %w", err)
	}

	linkType := reader.LinkType()

	summary := DecodedCaptureSummary{
		FilePath: path,
		LinkType: linkType.String(),
	}

	var packets []DecodedCapturePacket
	packetNumber := 0

	for {
		data, captureInfo, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}

			return DecodedCaptureSummary{}, nil,
				fmt.Errorf(
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

		decoded := DecodePacket(data, linkType)

		packets = append(packets, DecodedCapturePacket{
			Number:      packetNumber,
			Timestamp:   captureInfo.Timestamp,
			CapturedLen: captureInfo.CaptureLength,
			OriginalLen: captureInfo.Length,
			DecodedPacket: decoded,
		})

		if decoded.HasIPv4 {
			summary.IPv4Packets++
		}

		if decoded.HasIPv6 {
			summary.IPv6Packets++
		}

		if decoded.HasTCP {
			summary.TCPPackets++
		}

		if decoded.HasUDP {
			summary.UDPPackets++
		}
	}

	summary.PacketCount = packetNumber

	if packetNumber > 0 {
		summary.Duration =
			summary.LastTimestamp.Sub(summary.FirstTimestamp)
	}

	return summary, packets, nil
}