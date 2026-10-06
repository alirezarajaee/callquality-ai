package rtp

import (
	"encoding/binary"
	"fmt"
)

const fixedHeaderSize = 12

type Packet struct {
	Version uint8

	Padding   bool
	Extension bool

	CSRCCount uint8
	Marker    bool

	PayloadType uint8

	SequenceNumber uint16
	Timestamp      uint32
	SSRC           uint32

	HeaderLength  int
	PayloadLength int

	Payload []byte
}

func Parse(data []byte) (Packet, error) {
	if len(data) < fixedHeaderSize {
		return Packet{}, fmt.Errorf(
			"RTP packet too short: got %d bytes, need at least %d",
			len(data),
			fixedHeaderSize,
		)
	}

	version := data[0] >> 6

	if version != 2 {
		return Packet{}, fmt.Errorf(
			"unsupported RTP version: %d",
			version,
		)
	}

	padding := data[0]&0x20 != 0
	extension := data[0]&0x10 != 0
	csrcCount := data[0] & 0x0F

	marker := data[1]&0x80 != 0
	payloadType := data[1] & 0x7F

	sequenceNumber := binary.BigEndian.Uint16(data[2:4])
	timestamp := binary.BigEndian.Uint32(data[4:8])
	ssrc := binary.BigEndian.Uint32(data[8:12])

	headerLength := fixedHeaderSize +
		int(csrcCount)*4

	if len(data) < headerLength {
		return Packet{}, fmt.Errorf(
			"RTP packet shorter than fixed header plus CSRC list",
		)
	}

	if extension {
		const extensionHeaderSize = 4

		if len(data) < headerLength+extensionHeaderSize {
			return Packet{}, fmt.Errorf(
				"RTP extension header is truncated",
			)
		}

		extensionLengthWords := binary.BigEndian.Uint16(
			data[headerLength+2 : headerLength+4],
		)

		extensionLengthBytes := int(extensionLengthWords) * 4

		headerLength += extensionHeaderSize +
			extensionLengthBytes

		if len(data) < headerLength {
			return Packet{}, fmt.Errorf(
				"RTP extension data is truncated",
			)
		}
	}

	payloadEnd := len(data)

	if padding {
		paddingLength := int(data[len(data)-1])

		if paddingLength == 0 {
			return Packet{}, fmt.Errorf(
				"RTP padding flag set with zero padding length",
			)
		}

		if paddingLength > payloadEnd-headerLength {
			return Packet{}, fmt.Errorf(
				"RTP padding exceeds available payload",
			)
		}

		payloadEnd -= paddingLength
	}

	if payloadEnd < headerLength {
		return Packet{}, fmt.Errorf(
			"RTP payload boundary is invalid",
		)
	}

	payload := append(
		[]byte(nil),
		data[headerLength:payloadEnd]...,
	)

	return Packet{
		Version:         version,
		Padding:         padding,
		Extension:       extension,
		CSRCCount:       csrcCount,
		Marker:          marker,
		PayloadType:     payloadType,
		SequenceNumber:  sequenceNumber,
		Timestamp:       timestamp,
		SSRC:             ssrc,
		HeaderLength:     headerLength,
		PayloadLength:    len(payload),
		Payload:          payload,
	}, nil
}