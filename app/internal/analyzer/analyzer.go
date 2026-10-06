package analyzer

import (
	"fmt"

	"github.com/alirezarajaee/callquality-ai/app/internal/pcap"
	"github.com/alirezarajaee/callquality-ai/app/internal/sip"
)

type AnalyzedPacket struct {
	Packet     pcap.DecodedCapturePacket
	SIP        sip.DetectionResult
	SIPMessage sip.Message
}

type AnalysisSummary struct {
	pcap.DecodedCaptureSummary

	SIPPackets   int
	SIPRequests  int
	SIPResponses int
	SIPUnknown   int
}

func AnalyzeFile(
	path string,
) (AnalysisSummary, []AnalyzedPacket, error) {
	captureSummary, packets, err := pcap.ReadAndDecodeFile(path)
	if err != nil {
		return AnalysisSummary{}, nil, fmt.Errorf(
			"read and decode capture: %w",
			err,
		)
	}

	summary := AnalysisSummary{
		DecodedCaptureSummary: captureSummary,
	}

	analyzedPackets := make([]AnalyzedPacket, 0, len(packets))

	for _, packet := range packets {
		decoded := packet.DecodedPacket

		analyzedPacket := AnalyzedPacket{
			Packet: packet,
		}

		if (decoded.HasUDP || decoded.HasTCP) &&
			len(decoded.Payload) > 0 {
			message, ok := sip.ParseMessage(
				decoded.Payload,
				decoded.SourcePort,
				decoded.DestinationPort,
			)

			if ok {
				analyzedPacket.SIP = message.Detection
				analyzedPacket.SIPMessage = message

				summary.SIPPackets++

				switch message.Detection.MessageType {
				case sip.MessageTypeRequest:
					summary.SIPRequests++

				case sip.MessageTypeResponse:
					summary.SIPResponses++

				default:
					summary.SIPUnknown++
				}
			}
		}

		analyzedPackets = append(
			analyzedPackets,
			analyzedPacket,
		)
	}

	return summary, analyzedPackets, nil
}