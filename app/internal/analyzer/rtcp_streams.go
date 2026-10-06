package analyzer

import (
	"time"

	"github.com/alirezarajaee/callquality-ai/app/internal/pcap"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtcp"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
)

// RTCPSenderReport contains the RTCP Sender Report information
// correlated with an existing RTP stream.
type RTCPSenderReport struct {
	CapturedAt time.Time

	NTPShort          uint32
	RTPTimestamp      uint32
	SenderPacketCount uint32
	SenderOctetCount  uint32
}

// RTCPStreamResult contains RTCP information correlated with one
// RTP stream belonging to one reconstructed call.
type RTCPStreamResult struct {
	CallID string

	Key         rtp.StreamKey
	PayloadType uint8

	SenderReports      []RTCPSenderReport
	ReportObservations []rtcp.ReportObservation
}

type rtcpResultKey struct {
	callID string
	stream rtp.StreamKey
}

// CorrelateRTCPWithRTPStreams parses RTCP packets from the analyzed
// capture and associates them with already reconstructed RTP streams.
//
// Correlation uses:
//
//   - RTCP SR SSRC -> RTP stream SSRC
//   - RTCP RR report-block SSRC -> RTP stream SSRC
//   - source/destination IP direction
//   - RTP/RTCP port relationship
//
// The function does not mutate the input calls or packets.
func CorrelateRTCPWithRTPStreams(
	calls []Call,
	packets []AnalyzedPacket,
) []RTCPStreamResult {
	if len(calls) == 0 || len(packets) == 0 {
		return nil
	}

	resultsByKey := make(map[rtcpResultKey]*RTCPStreamResult)
	resultOrder := make([]rtcpResultKey, 0)

	correlator := rtcp.NewCorrelator()

	for _, analyzed := range packets {
		decoded := analyzed.Packet.DecodedPacket

		detection := rtcp.Detect(decoded.Payload)
		if !detection.IsRTCP {
			continue
		}

		compound, err := rtcp.ParseCompound(decoded.Payload)
		if err != nil {
			continue
		}

		for _, rtcpPacket := range compound {
			switch rtcpPacket.PacketType {
			case 200:
				stream, callID, ok := findRTCPStreamForSenderReport(
					calls,
					decoded.SourceIP,
					decoded.DestinationIP,
					decoded.SourcePort,
					decoded.DestinationPort,
					rtcpPacket.SSRC,
				)

				if !ok {
					// Keep the SR in the correlator even when it cannot
					// currently be attached to an RTP stream. A later RR
					// may still be useful for protocol-level correlation.
					correlator.Observe(
						analyzed.Packet.Timestamp,
						rtcpPacket,
						0,
					)
					continue
				}

				key := rtcpResultKey{
					callID: callID,
					stream: stream.Key,
				}

				result := getOrCreateRTCPResult(
					resultsByKey,
					&resultOrder,
					key,
					stream,
				)

				if rtcpPacket.SenderInfo != nil {
					ntpShort := rtcp.NTPShort(
						rtcpPacket.SenderInfo.NTPSeconds,
						rtcpPacket.SenderInfo.NTPFraction,
					)

					result.SenderReports = append(
						result.SenderReports,
						RTCPSenderReport{
							CapturedAt:        analyzed.Packet.Timestamp,
							NTPShort:          ntpShort,
							RTPTimestamp:      rtcpPacket.SenderInfo.RTPTimestamp,
							SenderPacketCount: rtcpPacket.SenderInfo.SenderPacketCount,
							SenderOctetCount:  rtcpPacket.SenderInfo.SenderOctetCount,
						},
					)
				}

				correlator.Observe(
					analyzed.Packet.Timestamp,
					rtcpPacket,
					0,
				)

			case 201:
				if len(rtcpPacket.ReportBlocks) == 0 {
					continue
				}

				observations := correlator.Observe(
					analyzed.Packet.Timestamp,
					rtcpPacket,
					0,
				)

				for index, block := range rtcpPacket.ReportBlocks {
					stream, callID, ok := findRTCPStreamForReceiverReport(
						calls,
						decoded.SourceIP,
						decoded.DestinationIP,
						decoded.SourcePort,
						decoded.DestinationPort,
						block.SSRC,
					)

					if !ok {
						continue
					}

					key := rtcpResultKey{
						callID: callID,
						stream: stream.Key,
					}

					result := getOrCreateRTCPResult(
						resultsByKey,
						&resultOrder,
						key,
						stream,
					)

					if index >= len(observations) {
						continue
					}

					observation := observations[index]

					// Clock-rate enrichment happens in the unified
					// media-metrics stage. Until then, RTCP jitter
					// remains available in timestamp units.
					if !observation.Metrics.JitterAvailable {
						observation.Metrics.JitterMilliseconds = 0
					}

					result.ReportObservations = append(
						result.ReportObservations,
						observation,
					)
				}

			default:
				// Other RTCP packet types are intentionally ignored here.
			}
		}
	}

	results := make(
		[]RTCPStreamResult,
		0,
		len(resultOrder),
	)

	for _, key := range resultOrder {
		result := resultsByKey[key]
		if result == nil {
			continue
		}

		results = append(results, *result)
	}

	return results
}

func getOrCreateRTCPResult(
	resultsByKey map[rtcpResultKey]*RTCPStreamResult,
	resultOrder *[]rtcpResultKey,
	key rtcpResultKey,
	stream RTPStreamResult,
) *RTCPStreamResult {
	if result, ok := resultsByKey[key]; ok {
		return result
	}

	result := &RTCPStreamResult{
		CallID:      key.callID,
		Key:         key.stream,
		PayloadType: stream.PayloadType,
	}

	resultsByKey[key] = result
	*resultOrder = append(*resultOrder, key)

	return result
}

func findRTCPStreamForSenderReport(
	calls []Call,
	sourceIP string,
	destinationIP string,
	sourcePort uint16,
	destinationPort uint16,
	ssrc uint32,
) (RTPStreamResult, string, bool) {
	var (
		bestScore  int
		bestCall   string
		bestStream RTPStreamResult
		found      bool
	)

	for _, call := range calls {
		for _, stream := range call.RTPStreams {
			if stream.Key.SSRC != ssrc {
				continue
			}

			score := scoreForwardRTCPPath(
				stream.Key,
				sourceIP,
				destinationIP,
				sourcePort,
				destinationPort,
			)

			if score <= 0 {
				continue
			}

			if !found || score > bestScore {
				found = true
				bestScore = score
				bestCall = call.CallID
				bestStream = stream
			}
		}
	}

	return bestStream, bestCall, found
}

func findRTCPStreamForReceiverReport(
	calls []Call,
	sourceIP string,
	destinationIP string,
	sourcePort uint16,
	destinationPort uint16,
	targetSSRC uint32,
) (RTPStreamResult, string, bool) {
	var (
		bestScore  int
		bestCall   string
		bestStream RTPStreamResult
		found      bool
	)

	for _, call := range calls {
		for _, stream := range call.RTPStreams {
			if stream.Key.SSRC != targetSSRC {
				continue
			}

			score := scoreReverseRTCPPath(
				stream.Key,
				sourceIP,
				destinationIP,
				sourcePort,
				destinationPort,
			)

			if score <= 0 {
				continue
			}

			if !found || score > bestScore {
				found = true
				bestScore = score
				bestCall = call.CallID
				bestStream = stream
			}
		}
	}

	return bestStream, bestCall, found
}

func scoreForwardRTCPPath(
	stream rtp.StreamKey,
	sourceIP string,
	destinationIP string,
	sourcePort uint16,
	destinationPort uint16,
) int {
	score := 0

	if stream.SourceIP == sourceIP {
		score += 5
	}

	if stream.DestinationIP == destinationIP {
		score += 5
	}

	if score < 10 {
		return 0
	}

	if rtcpPortsMatch(
		stream.SourcePort,
		sourcePort,
	) {
		score += 3
	}

	if rtcpPortsMatch(
		stream.DestinationPort,
		destinationPort,
	) {
		score += 3
	}

	return score
}

func scoreReverseRTCPPath(
	stream rtp.StreamKey,
	sourceIP string,
	destinationIP string,
	sourcePort uint16,
	destinationPort uint16,
) int {
	score := 0

	if stream.DestinationIP == sourceIP {
		score += 5
	}

	if stream.SourceIP == destinationIP {
		score += 5
	}

	if score < 10 {
		return 0
	}

	if rtcpPortsMatch(
		stream.DestinationPort,
		sourcePort,
	) {
		score += 3
	}

	if rtcpPortsMatch(
		stream.SourcePort,
		destinationPort,
	) {
		score += 3
	}

	return score
}

func rtcpPortsMatch(
	rtpPort uint16,
	rtcpPort uint16,
) bool {
	if rtpPort == 0 || rtcpPort == 0 {
		return false
	}

	// RTP/RTCP multiplexing.
	if rtcpPort == rtpPort {
		return true
	}

	// Traditional RTP/RTCP pairing.
	if rtpPort < 65535 &&
		rtcpPort == rtpPort+1 {
		return true
	}

	return false
}

// Ensure the compiler keeps the pcap import tied to the actual
// capture packet model used by this analyzer package.
var _ pcap.DecodedPacket
