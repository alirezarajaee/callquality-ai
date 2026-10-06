package analyzer

import (
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/alirezarajaee/callquality-ai/app/internal/pcap"
	"github.com/alirezarajaee/callquality-ai/app/internal/rtp"
)

func buildIntegrationRTCPPacket(
	packetType uint8,
	count uint8,
	body []byte,
) []byte {
	totalLength := 4 + len(body)

	if totalLength%4 != 0 {
		panic("RTCP test packet must be 32-bit aligned")
	}

	packet := make([]byte, totalLength)

	packet[0] = 0x80 | (count & 0x1f)
	packet[1] = packetType

	binary.BigEndian.PutUint16(
		packet[2:4],
		uint16(totalLength/4-1),
	)

	copy(packet[4:], body)

	return packet
}

func buildIntegrationSenderReport(
	ssrc uint32,
	ntpSeconds uint32,
	ntpFraction uint32,
) []byte {
	body := make([]byte, 24)

	binary.BigEndian.PutUint32(
		body[0:4],
		ssrc,
	)

	binary.BigEndian.PutUint32(
		body[4:8],
		ntpSeconds,
	)

	binary.BigEndian.PutUint32(
		body[8:12],
		ntpFraction,
	)

	binary.BigEndian.PutUint32(
		body[12:16],
		16000,
	)

	binary.BigEndian.PutUint32(
		body[16:20],
		100,
	)

	binary.BigEndian.PutUint32(
		body[20:24],
		16000,
	)

	return buildIntegrationRTCPPacket(
		200,
		0,
		body,
	)
}

func buildIntegrationReceiverReport(
	reporterSSRC uint32,
	targetSSRC uint32,
	lsr uint32,
	dlsr uint32,
) []byte {
	body := make([]byte, 28)

	binary.BigEndian.PutUint32(
		body[0:4],
		reporterSSRC,
	)

	binary.BigEndian.PutUint32(
		body[4:8],
		targetSSRC,
	)

	body[8] = 32

	// Signed 24-bit cumulative loss.
	body[9] = 0
	body[10] = 0
	body[11] = 4

	binary.BigEndian.PutUint32(
		body[12:16],
		1200,
	)

	binary.BigEndian.PutUint32(
		body[16:20],
		80,
	)

	binary.BigEndian.PutUint32(
		body[20:24],
		lsr,
	)

	binary.BigEndian.PutUint32(
		body[24:28],
		dlsr,
	)

	return buildIntegrationRTCPPacket(
		201,
		1,
		body,
	)
}

func buildAnalyzedUDP(
	payload []byte,
	sourceIP string,
	destinationIP string,
	sourcePort uint16,
	destinationPort uint16,
	timestamp time.Time,
) AnalyzedPacket {
	return AnalyzedPacket{
		Packet: pcap.DecodedCapturePacket{
			Timestamp: timestamp,
			DecodedPacket: pcap.DecodedPacket{
				SourceIP:          sourceIP,
				DestinationIP:     destinationIP,
				SourcePort:        sourcePort,
				DestinationPort:   destinationPort,
				Payload:           payload,
				PayloadLength:     len(payload),
				HasUDP:            true,
				TransportProtocol: "UDP",
			},
		},
	}
}

func TestCorrelateRTCPWithRTPStreams(t *testing.T) {
	const (
		streamSSRC   = uint32(0x11223344)
		receiverSSRC = uint32(0x55667788)

		sourceIP      = "10.10.0.1"
		destinationIP = "10.10.0.2"

		rtpSourcePort      = uint16(10000)
		rtpDestinationPort = uint16(20000)
	)

	baseTime := time.Date(
		2026,
		1,
		1,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	rtpStream := RTPStreamResult{
		Key: rtp.StreamKey{
			SSRC:            streamSSRC,
			SourceIP:        sourceIP,
			DestinationIP:   destinationIP,
			SourcePort:      rtpSourcePort,
			DestinationPort: rtpDestinationPort,
		},
		PayloadType: 0,
	}

	calls := []Call{
		{
			CallID:     "call-001",
			RTPStreams: []RTPStreamResult{rtpStream},
		},
	}

	ntpSeconds := uint32(0x12345678)
	ntpFraction := uint32(0x9abcdef0)

	lsr := uint32(
		(ntpSeconds << 16) |
			(ntpFraction >> 16),
	)

	dlsr := uint32(22938)

	senderReport := buildIntegrationSenderReport(
		streamSSRC,
		ntpSeconds,
		ntpFraction,
	)

	receiverReport := buildIntegrationReceiverReport(
		receiverSSRC,
		streamSSRC,
		lsr,
		dlsr,
	)

	packets := []AnalyzedPacket{
		buildAnalyzedUDP(
			senderReport,
			sourceIP,
			destinationIP,
			rtpSourcePort+1,
			rtpDestinationPort+1,
			baseTime,
		),
		buildAnalyzedUDP(
			receiverReport,
			destinationIP,
			sourceIP,
			rtpDestinationPort+1,
			rtpSourcePort+1,
			baseTime.Add(
				1*time.Second+350*time.Millisecond,
			),
		),
	}

	results := CorrelateRTCPWithRTPStreams(
		calls,
		packets,
	)

	if len(results) != 1 {
		t.Fatalf(
			"result count mismatch: got %d want 1",
			len(results),
		)
	}

	result := results[0]

	if result.CallID != "call-001" {
		t.Fatalf(
			"call ID mismatch: got %q want %q",
			result.CallID,
			"call-001",
		)
	}

	if result.Key.SSRC != streamSSRC {
		t.Fatalf(
			"stream SSRC mismatch: got 0x%08x want 0x%08x",
			result.Key.SSRC,
			streamSSRC,
		)
	}

	if result.PayloadType != 0 {
		t.Fatalf(
			"payload type mismatch: got %d want 0",
			result.PayloadType,
		)
	}

	if len(result.SenderReports) != 1 {
		t.Fatalf(
			"sender report count mismatch: got %d want 1",
			len(result.SenderReports),
		)
	}

	if result.SenderReports[0].NTPShort != lsr {
		t.Fatalf(
			"NTP short mismatch: got 0x%08x want 0x%08x",
			result.SenderReports[0].NTPShort,
			lsr,
		)
	}

	if len(result.ReportObservations) != 1 {
		t.Fatalf(
			"report observation count mismatch: got %d want 1",
			len(result.ReportObservations),
		)
	}

	observation := result.ReportObservations[0]

	if observation.TargetSSRC != streamSSRC {
		t.Fatalf(
			"target SSRC mismatch: got 0x%08x want 0x%08x",
			observation.TargetSSRC,
			streamSSRC,
		)
	}

	if observation.ReporterSSRC != receiverSSRC {
		t.Fatalf(
			"reporter SSRC mismatch: got 0x%08x want 0x%08x",
			observation.ReporterSSRC,
			receiverSSRC,
		)
	}

	if math.Abs(
		observation.Metrics.FractionLostPercent-12.5,
	) > 1e-12 {
		t.Fatalf(
			"fraction lost mismatch: got %.12f want 12.5",
			observation.Metrics.FractionLostPercent,
		)
	}

	if observation.Metrics.CumulativePacketsLost != 4 {
		t.Fatalf(
			"cumulative loss mismatch: got %d want 4",
			observation.Metrics.CumulativePacketsLost,
		)
	}

	if observation.Metrics.JitterTimestampUnits != 80 {
		t.Fatalf(
			"jitter timestamp units mismatch: got %d want 80",
			observation.Metrics.JitterTimestampUnits,
		)
	}

	// The current integration stage does not yet know the codec clock rate,
	// therefore RTCP jitter in milliseconds is intentionally unavailable.
	if observation.Metrics.JitterAvailable {
		t.Fatal(
			"expected jitter milliseconds to be unavailable without clock rate",
		)
	}

	if !observation.PassiveRTTAvailable {
		t.Fatal("expected passive RTT to be available")
	}

	if math.Abs(
		observation.PassiveRTTSeconds-1.0,
	) > 0.002 {
		t.Fatalf(
			"passive RTT mismatch: got %.6f want approximately 1.0",
			observation.PassiveRTTSeconds,
		)
	}
}

func TestCorrelateRTCPDoesNotAttachWrongSSRC(t *testing.T) {
	const (
		streamSSRC = uint32(0x11223344)
		wrongSSRC  = uint32(0xAABBCCDD)
	)

	calls := []Call{
		{
			CallID: "call-001",
			RTPStreams: []RTPStreamResult{
				{
					Key: rtp.StreamKey{
						SSRC:            streamSSRC,
						SourceIP:        "10.10.0.1",
						DestinationIP:   "10.10.0.2",
						SourcePort:      10000,
						DestinationPort: 20000,
					},
					PayloadType: 0,
				},
			},
		},
	}

	senderReport := buildIntegrationSenderReport(
		wrongSSRC,
		0x12345678,
		0,
	)

	packets := []AnalyzedPacket{
		buildAnalyzedUDP(
			senderReport,
			"10.10.0.1",
			"10.10.0.2",
			10001,
			20001,
			time.Date(
				2026,
				1,
				1,
				12,
				0,
				0,
				0,
				time.UTC,
			),
		),
	}

	results := CorrelateRTCPWithRTPStreams(
		calls,
		packets,
	)

	if len(results) != 0 {
		t.Fatalf(
			"expected no correlation for wrong SSRC, got %d",
			len(results),
		)
	}
}

func TestCorrelateRTCPSupportsMuxedRTCPPort(t *testing.T) {
	const (
		streamSSRC = uint32(0x11223344)

		sourceIP      = "10.10.0.1"
		destinationIP = "10.10.0.2"

		rtpPort = uint16(12000)
	)

	calls := []Call{
		{
			CallID: "call-mux",
			RTPStreams: []RTPStreamResult{
				{
					Key: rtp.StreamKey{
						SSRC:            streamSSRC,
						SourceIP:        sourceIP,
						DestinationIP:   destinationIP,
						SourcePort:      rtpPort,
						DestinationPort: rtpPort,
					},
					PayloadType: 0,
				},
			},
		},
	}

	senderReport := buildIntegrationSenderReport(
		streamSSRC,
		0x01020304,
		0x05060708,
	)

	packets := []AnalyzedPacket{
		buildAnalyzedUDP(
			senderReport,
			sourceIP,
			destinationIP,
			rtpPort,
			rtpPort,
			time.Date(
				2026,
				1,
				1,
				12,
				0,
				0,
				0,
				time.UTC,
			),
		),
	}

	results := CorrelateRTCPWithRTPStreams(
		calls,
		packets,
	)

	if len(results) != 1 {
		t.Fatalf(
			"expected muxed RTCP to correlate, got %d results",
			len(results),
		)
	}

	if len(results[0].SenderReports) != 1 {
		t.Fatalf(
			"expected one sender report, got %d",
			len(results[0].SenderReports),
		)
	}
}
