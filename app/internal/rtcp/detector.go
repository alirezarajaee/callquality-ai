package rtcp

// Detection describes the result of inspecting a UDP payload
// to determine whether it contains an RTCP compound packet.
type Detection struct {
	IsRTCP bool

	PacketCount int
	PacketTypes []uint8

	HasSenderReport   bool
	HasReceiverReport bool
}

// Detect inspects a UDP payload and determines whether it has the
// structure of a common RTCP packet or compound RTCP packet.
//
// The detector intentionally accepts the commonly assigned RTCP
// packet-type range 192-223. This covers standard RTCP SR/RR/SDES/BYE/APP
// plus the feedback and extended-report families commonly encountered
// in RTP deployments.
//
// This function is intended as a protocol detector, not as a cryptographic
// validator for SRTP/SRTCP.
func Detect(data []byte) Detection {
	result := Detection{
		IsRTCP:      false,
		PacketTypes: nil,
	}

	packets, err := ParseCompound(data)
	if err != nil || len(packets) == 0 {
		return result
	}

	packetTypes := make([]uint8, 0, len(packets))

	for _, packet := range packets {
		if !isCommonRTCPPacketType(packet.PacketType) {
			return result
		}

		packetTypes = append(
			packetTypes,
			packet.PacketType,
		)
	}

	result.IsRTCP = true
	result.PacketCount = len(packets)
	result.PacketTypes = packetTypes

	for _, packetType := range packetTypes {
		switch packetType {
		case packetTypeSenderReport:
			result.HasSenderReport = true

		case packetTypeReceiverReport:
			result.HasReceiverReport = true
		}
	}

	return result
}

func isCommonRTCPPacketType(packetType uint8) bool {
	return packetType >= 192 && packetType <= 223
}

// IsRTCP is a convenience wrapper for callers that only need a boolean.
func IsRTCP(data []byte) bool {
	return Detect(data).IsRTCP
}
