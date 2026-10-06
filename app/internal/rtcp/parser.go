package rtcp

import (
	"encoding/binary"
	"fmt"
)

const (
	rtcpVersion = 2

	packetTypeSenderReport   = 200
	packetTypeReceiverReport = 201

	rtcpHeaderLen  = 4
	reportBlockLen = 24
)

// Packet represents one RTCP packet from a compound RTCP datagram.
type Packet struct {
	Version    uint8
	Padding    bool
	Count      uint8
	PacketType uint8
	Length     uint16

	SSRC uint32

	SenderInfo   *SenderInfo
	ReportBlocks []ReportBlock
}

// SenderInfo contains the sender information section of an RTCP Sender Report.
type SenderInfo struct {
	NTPSeconds        uint32
	NTPFraction       uint32
	RTPTimestamp      uint32
	SenderPacketCount uint32
	SenderOctetCount  uint32
}

// ReportBlock contains one RTCP reception report block.
type ReportBlock struct {
	SSRC                       uint32
	FractionLost               uint8
	CumulativePacketsLost      int32
	HighestSequenceNumber      uint32
	Jitter                     uint32
	LastSenderReport           uint32
	DelaySinceLastSenderReport uint32
}

// ParseCompound parses one or more concatenated RTCP packets.
func ParseCompound(data []byte) ([]Packet, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("rtcp: empty packet")
	}

	packets := make([]Packet, 0, 2)

	for offset := 0; offset < len(data); {
		remaining := len(data) - offset

		if remaining < rtcpHeaderLen {
			return nil, fmt.Errorf(
				"rtcp: truncated header at offset %d",
				offset,
			)
		}

		header := data[offset : offset+rtcpHeaderLen]

		version := header[0] >> 6
		if version != rtcpVersion {
			return nil, fmt.Errorf(
				"rtcp: unsupported version %d at offset %d",
				version,
				offset,
			)
		}

		padding := (header[0] & 0x20) != 0
		count := header[0] & 0x1f
		packetType := header[1]

		lengthWords := binary.BigEndian.Uint16(header[2:4])
		packetLength := (int(lengthWords) + 1) * 4

		if packetLength < rtcpHeaderLen {
			return nil, fmt.Errorf(
				"rtcp: invalid packet length %d at offset %d",
				packetLength,
				offset,
			)
		}

		if packetLength > remaining {
			return nil, fmt.Errorf(
				"rtcp: truncated packet at offset %d: need %d bytes, have %d",
				offset,
				packetLength,
				remaining,
			)
		}

		packetData := data[offset : offset+packetLength]

		contentEnd := packetLength

		if padding {
			paddingCount := int(packetData[packetLength-1])

			if paddingCount == 0 ||
				paddingCount > packetLength-rtcpHeaderLen {
				return nil, fmt.Errorf(
					"rtcp: invalid padding count %d at offset %d",
					paddingCount,
					offset,
				)
			}

			contentEnd -= paddingCount
		}

		content := packetData[:contentEnd]

		packet := Packet{
			Version:    version,
			Padding:    padding,
			Count:      count,
			PacketType: packetType,
			Length:     lengthWords,
		}

		switch packetType {
		case packetTypeSenderReport:
			if err := parseSenderReport(content, &packet); err != nil {
				return nil, fmt.Errorf(
					"rtcp SR at offset %d: %w",
					offset,
					err,
				)
			}

		case packetTypeReceiverReport:
			if err := parseReceiverReport(content, &packet); err != nil {
				return nil, fmt.Errorf(
					"rtcp RR at offset %d: %w",
					offset,
					err,
				)
			}

		default:
			// Keep the common RTCP header for packet types
			// that are not implemented yet.
		}

		packets = append(packets, packet)
		offset += packetLength
	}

	return packets, nil
}

func parseSenderReport(data []byte, packet *Packet) error {
	const senderReportMinLen = rtcpHeaderLen + 24

	if len(data) < senderReportMinLen {
		return fmt.Errorf(
			"packet too short: need at least %d bytes, have %d",
			senderReportMinLen,
			len(data),
		)
	}

	packet.SSRC = binary.BigEndian.Uint32(data[4:8])

	packet.SenderInfo = &SenderInfo{
		NTPSeconds:        binary.BigEndian.Uint32(data[8:12]),
		NTPFraction:       binary.BigEndian.Uint32(data[12:16]),
		RTPTimestamp:      binary.BigEndian.Uint32(data[16:20]),
		SenderPacketCount: binary.BigEndian.Uint32(data[20:24]),
		SenderOctetCount:  binary.BigEndian.Uint32(data[24:28]),
	}

	expectedLen := senderReportMinLen +
		int(packet.Count)*reportBlockLen

	if len(data) < expectedLen {
		return fmt.Errorf(
			"truncated report blocks: need %d bytes, have %d",
			expectedLen,
			len(data),
		)
	}

	if len(data) != expectedLen {
		return fmt.Errorf(
			"unexpected packet size: expected %d bytes, have %d",
			expectedLen,
			len(data),
		)
	}

	packet.ReportBlocks = make([]ReportBlock, 0, packet.Count)

	offset := senderReportMinLen

	for i := 0; i < int(packet.Count); i++ {
		block, err := parseReportBlock(
			data[offset : offset+reportBlockLen],
		)
		if err != nil {
			return fmt.Errorf(
				"report block %d: %w",
				i,
				err,
			)
		}

		packet.ReportBlocks = append(
			packet.ReportBlocks,
			block,
		)

		offset += reportBlockLen
	}

	return nil
}

func parseReceiverReport(data []byte, packet *Packet) error {
	const receiverReportMinLen = rtcpHeaderLen + 4

	if len(data) < receiverReportMinLen {
		return fmt.Errorf(
			"packet too short: need at least %d bytes, have %d",
			receiverReportMinLen,
			len(data),
		)
	}

	packet.SSRC = binary.BigEndian.Uint32(data[4:8])

	expectedLen := receiverReportMinLen +
		int(packet.Count)*reportBlockLen

	if len(data) < expectedLen {
		return fmt.Errorf(
			"truncated report blocks: need %d bytes, have %d",
			expectedLen,
			len(data),
		)
	}

	if len(data) != expectedLen {
		return fmt.Errorf(
			"unexpected packet size: expected %d bytes, have %d",
			expectedLen,
			len(data),
		)
	}

	packet.ReportBlocks = make([]ReportBlock, 0, packet.Count)

	offset := receiverReportMinLen

	for i := 0; i < int(packet.Count); i++ {
		block, err := parseReportBlock(
			data[offset : offset+reportBlockLen],
		)
		if err != nil {
			return fmt.Errorf(
				"report block %d: %w",
				i,
				err,
			)
		}

		packet.ReportBlocks = append(
			packet.ReportBlocks,
			block,
		)

		offset += reportBlockLen
	}

	return nil
}

func parseReportBlock(data []byte) (ReportBlock, error) {
	if len(data) < reportBlockLen {
		return ReportBlock{}, fmt.Errorf(
			"need %d bytes, have %d",
			reportBlockLen,
			len(data),
		)
	}

	cumulativeLost :=
		int32(data[5])<<16 |
			int32(data[6])<<8 |
			int32(data[7])

	// Cumulative packets lost is a signed 24-bit integer.
	if cumulativeLost&0x00800000 != 0 {
		cumulativeLost -= 1 << 24
	}

	return ReportBlock{
		SSRC:                       binary.BigEndian.Uint32(data[0:4]),
		FractionLost:               data[4],
		CumulativePacketsLost:      cumulativeLost,
		HighestSequenceNumber:      binary.BigEndian.Uint32(data[8:12]),
		Jitter:                     binary.BigEndian.Uint32(data[12:16]),
		LastSenderReport:           binary.BigEndian.Uint32(data[16:20]),
		DelaySinceLastSenderReport: binary.BigEndian.Uint32(data[20:24]),
	}, nil
}