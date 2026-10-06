package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const (
	defaultOutput       = "../samples/synthetic-call.pcap"
	defaultDropRTPIndex = 20

	ipA = "10.10.0.1"
	ipB = "10.10.0.2"

	sipPort = 5060

	rtpPortA = 10000
	rtpPortB = 20000

	rtcpPortA = 10001
	rtcpPortB = 20001

	ssrcA uint32 = 0x11111111
	ssrcB uint32 = 0x22222222

	startSequenceA uint16 = 1000
	startSequenceB uint16 = 2000

	startRTPTimestampA uint32 = 16000
	startRTPTimestampB uint32 = 32000

	packetCount = 50

	rtpPayloadSize = 160
)

var (
	macA = net.HardwareAddr{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	macB = net.HardwareAddr{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
)

type packetSpec struct {
	at time.Time

	sourceIP      string
	destinationIP string

	sourcePort      uint16
	destinationPort uint16

	payload []byte
}

func main() {
	outputFlag := flag.String(
		"output",
		defaultOutput,
		"output PCAP path",
	)
	dropRTPIndexFlag := flag.Int(
		"drop-rtp-index",
		defaultDropRTPIndex,
		"RTP packet index to omit for controlled loss; use -1 for no intentional loss",
	)

	flag.Parse()

	if *dropRTPIndexFlag < -1 || *dropRTPIndexFlag >= packetCount {
		fmt.Fprintf(os.Stderr, "Error: -drop-rtp-index must be -1 or between 0 and %d\n", packetCount-1)
		os.Exit(1)
	}

	outputPath := *outputFlag

	if err := generateCapture(outputPath, *dropRTPIndexFlag); err != nil {
		fmt.Fprintln(
			os.Stderr,
			"Error:",
			err,
		)
		os.Exit(1)
	}

	fmt.Printf(
		"Generated synthetic VoIP capture:\n%s\n",
		outputPath,
	)
	fmt.Printf(
		"Packets: SIP + SDP + RTP + RTCP\n",
	)
}

func generateCapture(outputPath string, dropRTPIndex int) error {
	if err := os.MkdirAll(
		filepath.Dir(outputPath),
		0o755,
	); err != nil {
		return fmt.Errorf(
			"create output directory: %w",
			err,
		)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf(
			"create output file: %w",
			err,
		)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)

	if err := writer.WriteFileHeader(
		65535,
		layers.LinkTypeEthernet,
	); err != nil {
		return fmt.Errorf(
			"write PCAP header: %w",
			err,
		)
	}

	start := time.Date(
		2026,
		1,
		1,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	packets := buildPackets(start, dropRTPIndex)

	for _, spec := range packets {
		data, err := serializeUDPPacket(spec)
		if err != nil {
			return fmt.Errorf(
				"serialize packet at %s: %w",
				spec.at.Format(time.RFC3339Nano),
				err,
			)
		}

		captureInfo := gopacket.CaptureInfo{
			Timestamp:     spec.at,
			CaptureLength: len(data),
			Length:        len(data),
		}

		if err := writer.WritePacket(
			captureInfo,
			data,
		); err != nil {
			return fmt.Errorf(
				"write packet: %w",
				err,
			)
		}
	}

	return nil
}

func buildPackets(start time.Time, dropRTPIndex int) []packetSpec {
	packets := make(
		[]packetSpec,
		0,
		120,
	)

	// SIP INVITE + SDP offer.
	inviteBody := buildSDPOffer()

	packets = append(
		packets,
		packetSpec{
			at:              start,
			sourceIP:        ipA,
			destinationIP:   ipB,
			sourcePort:      sipPort,
			destinationPort: sipPort,
			payload: buildSIPRequest(
				"INVITE",
				"sip:b@example.com",
				"a1",
				"",
				1,
				inviteBody,
			),
		},
	)

	// 180 Ringing.
	packets = append(
		packets,
		packetSpec{
			at:              start.Add(100 * time.Millisecond),
			sourceIP:        ipB,
			destinationIP:   ipA,
			sourcePort:      sipPort,
			destinationPort: sipPort,
			payload: buildSIPResponse(
				180,
				"Ringing",
				"a1",
				"b1",
				1,
			),
		},
	)

	// 200 OK + SDP answer.
	packets = append(
		packets,
		packetSpec{
			at:              start.Add(200 * time.Millisecond),
			sourceIP:        ipB,
			destinationIP:   ipA,
			sourcePort:      sipPort,
			destinationPort: sipPort,
			payload: buildSIPResponseWithBody(
				200,
				"OK",
				"a1",
				"b1",
				1,
				buildSDPAnswer(),
			),
		},
	)

	// ACK.
	packets = append(
		packets,
		packetSpec{
			at:              start.Add(250 * time.Millisecond),
			sourceIP:        ipA,
			destinationIP:   ipB,
			sourcePort:      sipPort,
			destinationPort: sipPort,
			payload: buildSIPRequest(
				"ACK",
				"sip:b@example.com",
				"a1",
				"b1",
				1,
				"",
			),
		},
	)

	// RTP A -> B.
	for i := 0; i < packetCount; i++ {
		if i == dropRTPIndex {
			// Optionally omit one RTP packet to create controlled loss.
			continue
		}

		sequence := startSequenceA + uint16(i)
		rtpTimestamp :=
			startRTPTimestampA +
				uint32(i*160)

		captureTime := start.
			Add(300 * time.Millisecond).
			Add(time.Duration(i) * 20 * time.Millisecond).
			Add(jitterPatternA(i))

		packets = append(
			packets,
			packetSpec{
				at:              captureTime,
				sourceIP:        ipA,
				destinationIP:   ipB,
				sourcePort:      rtpPortA,
				destinationPort: rtpPortB,
				payload: buildRTPPacket(
					sequence,
					rtpTimestamp,
					ssrcA,
					0,
					rtpPayloadSize,
				),
			},
		)
	}

	// RTP B -> A.
	for i := 0; i < packetCount; i++ {
		sequence := startSequenceB + uint16(i)
		rtpTimestamp :=
			startRTPTimestampB +
				uint32(i*160)

		captureTime := start.
			Add(320 * time.Millisecond).
			Add(time.Duration(i) * 20 * time.Millisecond).
			Add(jitterPatternB(i))

		packets = append(
			packets,
			packetSpec{
				at:              captureTime,
				sourceIP:        ipB,
				destinationIP:   ipA,
				sourcePort:      rtpPortB,
				destinationPort: rtpPortA,
				payload: buildRTPPacket(
					sequence,
					rtpTimestamp,
					ssrcB,
					0,
					rtpPayloadSize,
				),
			},
		)
	}

	// Sender Report from A. Keep the RTCP sender statistics consistent with
	// the RTP packets that were actually emitted.
	ntpSecondsA := uint32(0x12345678)
	ntpFractionA := uint32(0x80000000)
	sentPacketsA := packetCount
	if dropRTPIndex >= 0 {
		sentPacketsA--
	}

	packets = append(
		packets,
		packetSpec{
			at:              start.Add(900 * time.Millisecond),
			sourceIP:        ipA,
			destinationIP:   ipB,
			sourcePort:      rtcpPortA,
			destinationPort: rtcpPortB,
			payload: buildRTCPSenderReport(
				ssrcA,
				ntpSecondsA,
				ntpFractionA,
				startRTPTimestampA+7200,
				sentPacketsA,
				sentPacketsA*rtpPayloadSize,
			),
		},
	)

	// RR from B reporting A.
	lsrA := (ntpSecondsA << 16) |
		(ntpFractionA >> 16)

	lostPacketsA := 0
	if dropRTPIndex >= 0 {
		lostPacketsA = 1
	}
	fractionLostA := rtcpFractionLost(lostPacketsA, packetCount)

	packets = append(
		packets,
		packetSpec{
			at:              start.Add(1*time.Second + 100*time.Millisecond),
			sourceIP:        ipB,
			destinationIP:   ipA,
			sourcePort:      rtcpPortB,
			destinationPort: rtcpPortA,
			payload: buildRTCPReceiverReport(
				ssrcB,
				ssrcA,
				fractionLostA,
				int32(lostPacketsA),
				startSequenceA+uint16(packetCount-1),
				40,
				lsrA,
				3277,
			),
		},
	)

	// Sender Report from B.
	ntpSecondsB := uint32(0x22334455)
	ntpFractionB := uint32(0x40000000)

	packets = append(
		packets,
		packetSpec{
			at:              start.Add(920 * time.Millisecond),
			sourceIP:        ipB,
			destinationIP:   ipA,
			sourcePort:      rtcpPortB,
			destinationPort: rtcpPortA,
			payload: buildRTCPSenderReport(
				ssrcB,
				ntpSecondsB,
				ntpFractionB,
				startRTPTimestampB+7840,
				packetCount,
				packetCount*rtpPayloadSize,
			),
		},
	)

	// RR from A reporting B.
	lsrB := (ntpSecondsB << 16) |
		(ntpFractionB >> 16)

	packets = append(
		packets,
		packetSpec{
			at:              start.Add(1*time.Second + 120*time.Millisecond),
			sourceIP:        ipA,
			destinationIP:   ipB,
			sourcePort:      rtcpPortA,
			destinationPort: rtcpPortB,
			payload: buildRTCPReceiverReport(
				ssrcA,
				ssrcB,
				0,
				0,
				startSequenceB+uint16(packetCount-1),
				32,
				lsrB,
				3277,
			),
		},
	)

	// BYE.
	packets = append(
		packets,
		packetSpec{
			at:              start.Add(1*time.Second + 300*time.Millisecond),
			sourceIP:        ipA,
			destinationIP:   ipB,
			sourcePort:      sipPort,
			destinationPort: sipPort,
			payload: buildSIPRequest(
				"BYE",
				"sip:b@example.com",
				"a1",
				"b1",
				2,
				"",
			),
		},
	)

	// Sort by capture timestamp because the two RTP directions were
	// generated independently.
	for i := 1; i < len(packets); i++ {
		current := packets[i]

		j := i - 1

		for j >= 0 &&
			packets[j].at.After(current.at) {

			packets[j+1] = packets[j]
			j--
		}

		packets[j+1] = current
	}

	return packets
}

func serializeUDPPacket(
	spec packetSpec,
) ([]byte, error) {
	sourceIP := net.ParseIP(
		spec.sourceIP,
	).To4()

	destinationIP := net.ParseIP(
		spec.destinationIP,
	).To4()

	if sourceIP == nil ||
		destinationIP == nil {
		return nil, fmt.Errorf(
			"invalid IPv4 addresses",
		)
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       macForIP(spec.sourceIP),
		DstMAC:       macForIP(spec.destinationIP),
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    sourceIP,
		DstIP:    destinationIP,
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(
			spec.sourcePort,
		),
		DstPort: layers.UDPPort(
			spec.destinationPort,
		),
	}

	if err := udp.SetNetworkLayerForChecksum(
		ip,
	); err != nil {
		return nil, fmt.Errorf(
			"set UDP checksum layer: %w",
			err,
		)
	}

	buffer := gopacket.NewSerializeBuffer()

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(
		buffer,
		options,
		ethernet,
		ip,
		udp,
		gopacket.Payload(spec.payload),
	); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func macForIP(ip string) net.HardwareAddr {
	if ip == ipA {
		return macA
	}

	return macB
}

func buildSIPRequest(
	method string,
	requestURI string,
	fromTag string,
	toTag string,
	cseq int,
	body string,
) []byte {
	headers := fmt.Sprintf(
		"%s %s SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK-%s\r\n"+
			"From: <sip:a@example.com>;tag=%s\r\n"+
			"To: <%s>%s\r\n"+
			"Call-ID: synthetic-call-001@example.com\r\n"+
			"CSeq: %d %s\r\n"+
			"Contact: <sip:a@%s:5060>\r\n"+
			"Content-Type: application/sdp\r\n",
		method,
		requestURI,
		ipA,
		method,
		fromTag,
		requestURI,
		formatToTag(toTag),
		cseq,
		method,
		ipA,
	)

	if body == "" {
		headers =
			stringsReplace(
				headers,
				"Content-Type: application/sdp\r\n",
				"",
			)
	}

	return buildSIPMessage(
		headers,
		body,
	)
}

func buildSIPResponse(
	code int,
	reason string,
	fromTag string,
	toTag string,
	cseq int,
) []byte {
	return buildSIPResponseWithBody(
		code,
		reason,
		fromTag,
		toTag,
		cseq,
		"",
	)
}

func buildSIPResponseWithBody(
	code int,
	reason string,
	fromTag string,
	toTag string,
	cseq int,
	body string,
) []byte {
	headers := fmt.Sprintf(
		"SIP/2.0 %d %s\r\n"+
			"Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK-response\r\n"+
			"From: <sip:a@example.com>;tag=%s\r\n"+
			"To: <sip:b@example.com>%s\r\n"+
			"Call-ID: synthetic-call-001@example.com\r\n"+
			"CSeq: %d INVITE\r\n"+
			"Contact: <sip:b@%s:5060>\r\n",
		code,
		reason,
		ipA,
		fromTag,
		formatToTag(toTag),
		cseq,
		ipB,
	)

	if body != "" {
		headers +=
			"Content-Type: application/sdp\r\n"
	}

	return buildSIPMessage(
		headers,
		body,
	)
}

func buildSIPMessage(
	headers string,
	body string,
) []byte {
	headers += fmt.Sprintf(
		"Content-Length: %d\r\n",
		len(body),
	)

	headers += "\r\n"

	return []byte(
		headers + body,
	)
}

func formatToTag(tag string) string {
	if tag == "" {
		return ""
	}

	return ";tag=" + tag
}

func stringsReplace(
	value string,
	old string,
	new string,
) string {
	result := make(
		[]byte,
		0,
		len(value),
	)

	for i := 0; i < len(value); {
		if len(value)-i >= len(old) &&
			value[i:i+len(old)] == old {

			result = append(
				result,
				new...,
			)

			i += len(old)
			continue
		}

		result = append(
			result,
			value[i],
		)

		i++
	}

	return string(result)
}

func buildSDPOffer() string {
	return "v=0\r\n" +
		"o=- 1 1 IN IP4 " + ipA + "\r\n" +
		"s=CallQuality Synthetic Call\r\n" +
		"c=IN IP4 " + ipA + "\r\n" +
		"t=0 0\r\n" +
		"m=audio 10000 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=sendrecv\r\n"
}

func buildSDPAnswer() string {
	return "v=0\r\n" +
		"o=- 2 2 IN IP4 " + ipB + "\r\n" +
		"s=CallQuality Synthetic Call\r\n" +
		"c=IN IP4 " + ipB + "\r\n" +
		"t=0 0\r\n" +
		"m=audio 20000 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n" +
		"a=sendrecv\r\n"
}

func buildRTPPacket(
	sequence uint16,
	timestamp uint32,
	ssrc uint32,
	payloadType uint8,
	payloadSize int,
) []byte {
	packet := make(
		[]byte,
		12+payloadSize,
	)

	packet[0] = 0x80
	packet[1] = payloadType & 0x7f

	binary.BigEndian.PutUint16(
		packet[2:4],
		sequence,
	)

	binary.BigEndian.PutUint32(
		packet[4:8],
		timestamp,
	)

	binary.BigEndian.PutUint32(
		packet[8:12],
		ssrc,
	)

	for i := 12; i < len(packet); i++ {
		packet[i] = byte(
			(i + int(sequence)) % 255,
		)
	}

	return packet
}

func buildRTCPSenderReport(
	ssrc uint32,
	ntpSeconds uint32,
	ntpFraction uint32,
	rtpTimestamp uint32,
	packetCount int,
	octetCount int,
) []byte {
	packet := make(
		[]byte,
		28,
	)

	packet[0] = 0x80
	packet[1] = 200

	binary.BigEndian.PutUint16(
		packet[2:4],
		6,
	)

	binary.BigEndian.PutUint32(
		packet[4:8],
		ssrc,
	)

	binary.BigEndian.PutUint32(
		packet[8:12],
		ntpSeconds,
	)

	binary.BigEndian.PutUint32(
		packet[12:16],
		ntpFraction,
	)

	binary.BigEndian.PutUint32(
		packet[16:20],
		rtpTimestamp,
	)

	binary.BigEndian.PutUint32(
		packet[20:24],
		uint32(packetCount),
	)

	binary.BigEndian.PutUint32(
		packet[24:28],
		uint32(octetCount),
	)

	return packet
}

func rtcpFractionLost(lostPackets, expectedPackets int) uint8 {
	if lostPackets <= 0 || expectedPackets <= 0 {
		return 0
	}

	fraction := (lostPackets * 256) / expectedPackets
	if fraction > 255 {
		fraction = 255
	}

	return uint8(fraction)
}

func buildRTCPReceiverReport(
	reporterSSRC uint32,
	targetSSRC uint32,
	fractionLost uint8,
	cumulativeLost int32,
	highestSequence uint16,
	jitter uint32,
	lsr uint32,
	dlsr uint32,
) []byte {
	packet := make(
		[]byte,
		32,
	)

	packet[0] = 0x81
	packet[1] = 201

	binary.BigEndian.PutUint16(
		packet[2:4],
		7,
	)

	binary.BigEndian.PutUint32(
		packet[4:8],
		reporterSSRC,
	)

	binary.BigEndian.PutUint32(
		packet[8:12],
		targetSSRC,
	)

	packet[12] = fractionLost

	loss := cumulativeLost & 0x00ffffff

	packet[13] = byte(loss >> 16)
	packet[14] = byte(loss >> 8)
	packet[15] = byte(loss)

	binary.BigEndian.PutUint32(
		packet[16:20],
		uint32(highestSequence),
	)

	binary.BigEndian.PutUint32(
		packet[20:24],
		jitter,
	)

	binary.BigEndian.PutUint32(
		packet[24:28],
		lsr,
	)

	binary.BigEndian.PutUint32(
		packet[28:32],
		dlsr,
	)

	return packet
}

func jitterPatternA(i int) time.Duration {
	pattern := []time.Duration{
		0,
		2 * time.Millisecond,
		-1 * time.Millisecond,
		3 * time.Millisecond,
		-2 * time.Millisecond,
		1 * time.Millisecond,
	}

	return pattern[i%len(pattern)]
}

func jitterPatternB(i int) time.Duration {
	pattern := []time.Duration{
		0,
		1 * time.Millisecond,
		0,
		2 * time.Millisecond,
		-1 * time.Millisecond,
		1 * time.Millisecond,
	}

	return pattern[i%len(pattern)]
}
