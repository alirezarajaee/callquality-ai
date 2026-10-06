package analyzer

import (
	"sort"
	"strings"
	"time"

	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
)

type rtpStreamAccumulator struct {
	stream *rtp.Stream

	payloadTypes map[uint8]struct{}

	firstPacketTime  time.Time
	lastPacketTime   time.Time
	firstPayloadType uint8
}

func AttachRTPStreams(
	calls []Call,
	packets []AnalyzedPacket,
) []Call {
	result := cloneCalls(calls)

	accumulators := make(
		[]map[rtp.StreamKey]*rtpStreamAccumulator,
		len(result),
	)

	for i := range accumulators {
		accumulators[i] = make(
			map[rtp.StreamKey]*rtpStreamAccumulator,
		)
	}

	for _, analyzedPacket := range packets {
		decoded := analyzedPacket.Packet.DecodedPacket

		if !decoded.HasUDP || len(decoded.Payload) == 0 {
			continue
		}

		callIndex := findCallForTimestamp(
			result,
			analyzedPacket.Packet.Timestamp,
		)

		if callIndex < 0 {
			continue
		}

		call := &result[callIndex]

		rtpPacket, err := rtp.Parse(decoded.Payload)
		if err != nil {
			continue
		}

		endpoint := findMatchingMediaEndpoint(
			*call,
			decoded.SourceIP,
			decoded.SourcePort,
			decoded.DestinationIP,
			decoded.DestinationPort,
			rtpPacket.PayloadType,
		)

		if endpoint == nil {
			continue
		}

		key := rtp.StreamKey{
			SSRC:            rtpPacket.SSRC,
			SourceIP:        decoded.SourceIP,
			DestinationIP:   decoded.DestinationIP,
			SourcePort:      decoded.SourcePort,
			DestinationPort: decoded.DestinationPort,
		}

		accumulator, exists := accumulators[callIndex][key]

		if !exists {
			accumulator = &rtpStreamAccumulator{
				stream: rtp.NewStream(key),

				payloadTypes: make(
					map[uint8]struct{},
				),

				firstPayloadType: rtpPacket.PayloadType,
			}

			clockRate := codecClockRate(
				*endpoint,
				rtpPacket.PayloadType,
			)

			if clockRate > 0 {
				_ = accumulator.stream.ConfigureJitter(
					uint32(clockRate),
				)
			}

			accumulators[callIndex][key] = accumulator
		}

		accumulator.stream.Add(
			rtpPacket,
			analyzedPacket.Packet.Timestamp,
		)

		accumulator.payloadTypes[
			rtpPacket.PayloadType,
		] = struct{}{}

		packetTime := analyzedPacket.Packet.Timestamp

		if accumulator.firstPacketTime.IsZero() ||
			packetTime.Before(
				accumulator.firstPacketTime,
			) {
			accumulator.firstPacketTime = packetTime
		}

		if accumulator.lastPacketTime.IsZero() ||
			packetTime.After(
				accumulator.lastPacketTime,
			) {
			accumulator.lastPacketTime = packetTime
		}
	}

	for callIndex := range result {
		streamAccumulators := accumulators[callIndex]

		streams := make(
			[]RTPStreamResult,
			0,
			len(streamAccumulators),
		)

		for _, accumulator := range streamAccumulators {
			stats := accumulator.stream.Stats()

			streams = append(
				streams,
				RTPStreamResult{
					Key: accumulator.stream.Stats().Key,

					PayloadType:
						accumulator.firstPayloadType,

					FirstPacketTimestamp:
						accumulator.firstPacketTime.Format(
							time.RFC3339Nano,
						),

					LastPacketTimestamp:
						accumulator.lastPacketTime.Format(
							time.RFC3339Nano,
						),

					Stats: stats,
				},
			)
		}

		sort.SliceStable(
			streams,
			func(i, j int) bool {
				return streams[i].FirstPacketTimestamp <
					streams[j].FirstPacketTimestamp
			},
		)

		result[callIndex].RTPStreams = streams
	}

	return result
}

func cloneCalls(calls []Call) []Call {
	result := make([]Call, len(calls))

	for i := range calls {
		result[i] = calls[i]

		if calls[i].Messages != nil {
			result[i].Messages = append(
				[]SignalingEvent(nil),
				calls[i].Messages...,
			)
		}

		if calls[i].MediaEndpoints != nil {
			result[i].MediaEndpoints = append(
				[]MediaEndpoint(nil),
				calls[i].MediaEndpoints...,
			)
		}

		if calls[i].RTPStreams != nil {
			result[i].RTPStreams = append(
				[]RTPStreamResult(nil),
				calls[i].RTPStreams...,
			)
		}
	}

	return result
}

func findCallForTimestamp(
	calls []Call,
	timestamp time.Time,
) int {
	selected := -1

	for index, call := range calls {
		if call.StartTime.IsZero() {
			continue
		}

		if timestamp.Before(call.StartTime) {
			continue
		}

		if !call.EndTime.IsZero() &&
			timestamp.After(call.EndTime) {
			continue
		}

		if selected == -1 ||
			call.StartTime.After(
				calls[selected].StartTime,
			) {
			selected = index
		}
	}

	return selected
}

func findMatchingMediaEndpoint(
	call Call,
	sourceIP string,
	sourcePort uint16,
	destinationIP string,
	destinationPort uint16,
	payloadType uint8,
) *MediaEndpoint {
	for index := range call.MediaEndpoints {
		endpoint := &call.MediaEndpoints[index]

		if strings.ToLower(
			endpoint.MediaType,
		) != "audio" {
			continue
		}

		if endpoint.Address == "" {
			continue
		}

		if endpoint.Port <= 0 ||
			endpoint.Port > 65535 {
			continue
		}

		portMatches := false

		if endpoint.PortCount > 1 {
			portMatches =
				isPortInRange(
					endpoint.Port,
					endpoint.PortCount,
					sourcePort,
				) ||
					isPortInRange(
						endpoint.Port,
						endpoint.PortCount,
						destinationPort,
					)
		} else {
			portMatches =
				sourcePort == uint16(endpoint.Port) ||
					destinationPort == uint16(endpoint.Port)
		}

		if !portMatches {
			continue
		}

		if sourceIP != endpoint.Address &&
			destinationIP != endpoint.Address {
			continue
		}

		if !payloadTypeAllowed(
			endpoint.PayloadTypes,
			payloadType,
		) {
			continue
		}

		if !strings.Contains(
			strings.ToUpper(endpoint.Protocol),
			"RTP",
		) {
			continue
		}

		return endpoint
	}

	return nil
}

func matchesCallMediaEndpoint(
	call Call,
	sourceIP string,
	sourcePort uint16,
	destinationIP string,
	destinationPort uint16,
	payloadType uint8,
) bool {
	return findMatchingMediaEndpoint(
		call,
		sourceIP,
		sourcePort,
		destinationIP,
		destinationPort,
		payloadType,
	) != nil
}

func codecClockRate(
	endpoint MediaEndpoint,
	payloadType uint8,
) int {
	codec, ok := endpoint.Codecs[
		int(payloadType),
	]

	if !ok {
		return 0
	}

	return codec.ClockRate
}

func payloadTypeAllowed(
	payloadTypes []int,
	payloadType uint8,
) bool {
	for _, candidate := range payloadTypes {
		if candidate == int(payloadType) {
			return true
		}
	}

	return false
}

func isPortInRange(
	startPort int,
	portCount int,
	port uint16,
) bool {
	endPort := startPort + portCount - 1

	return int(port) >= startPort &&
		int(port) <= endPort
}