package rtcp

import "time"

const maxStoredSenderReports = 8

// ReportObservation is a normalized observation produced from
// an RTCP Sender Report or Receiver Report reception block.
type ReportObservation struct {
	CapturedAt time.Time

	PacketType uint8

	// ReporterSSRC identifies the participant that sent the RTCP packet.
	ReporterSSRC uint32

	// TargetSSRC identifies the RTP synchronization source described
	// by the reception report block.
	TargetSSRC uint32

	Metrics ReportMetrics

	// PassiveRTTSeconds is a PCAP-observed RTT estimate:
	//
	//   capture(RR) - capture(SR) - DLSR
	//
	// This is intentionally labeled passive because the capture timestamps
	// come from the packet capture clock, not from the RTP endpoint clock.
	PassiveRTTSeconds   float64
	PassiveRTTAvailable bool
}

// Correlator matches RTCP reception reports with previously observed
// Sender Reports using the LSR field.
type Correlator struct {
	senderReports map[uint32]map[uint32]time.Time
	reportOrder   map[uint32][]uint32
}

// NewCorrelator creates a new RTCP correlation engine.
func NewCorrelator() *Correlator {
	return &Correlator{
		senderReports: make(map[uint32]map[uint32]time.Time),
		reportOrder:   make(map[uint32][]uint32),
	}
}

// Observe consumes one parsed RTCP packet and returns observations for
// each reception report block contained in that packet.
//
// clockRate is the RTP media clock rate associated with the target SSRC.
// Pass zero when the clock rate is not known yet.
func (c *Correlator) Observe(
	capturedAt time.Time,
	packet Packet,
	clockRate uint32,
) []ReportObservation {
	if c == nil {
		return nil
	}

	// Save the Sender Report before processing report blocks so a later
	// RR can correlate against its LSR value.
	if packet.PacketType == packetTypeSenderReport &&
		packet.SenderInfo != nil {
		ntpShort := NTPShort(
			packet.SenderInfo.NTPSeconds,
			packet.SenderInfo.NTPFraction,
		)

		c.storeSenderReport(
			packet.SSRC,
			ntpShort,
			capturedAt,
		)
	}

	if len(packet.ReportBlocks) == 0 {
		return nil
	}

	observations := make(
		[]ReportObservation,
		0,
		len(packet.ReportBlocks),
	)

	for _, block := range packet.ReportBlocks {
		metrics := block.Metrics(clockRate)

		observation := ReportObservation{
			CapturedAt:   capturedAt,
			PacketType:   packet.PacketType,
			ReporterSSRC: packet.SSRC,
			TargetSSRC:   block.SSRC,
			Metrics:      metrics,
		}

		if block.LastSenderReport != 0 {
			if reports, ok := c.senderReports[block.SSRC]; ok {
				if senderCapturedAt, ok :=
					reports[block.LastSenderReport]; ok {

					elapsed := capturedAt.
						Sub(senderCapturedAt).
						Seconds()

					dlsr := DLSRSeconds(
						block.DelaySinceLastSenderReport,
					)

					if elapsed >= dlsr {
						observation.PassiveRTTSeconds =
							elapsed - dlsr
						observation.PassiveRTTAvailable = true
					}
				}
			}
		}

		observations = append(
			observations,
			observation,
		)
	}

	return observations
}

func (c *Correlator) storeSenderReport(
	ssrc uint32,
	ntpShort uint32,
	capturedAt time.Time,
) {
	reports, ok := c.senderReports[ssrc]
	if !ok {
		reports = make(map[uint32]time.Time)
		c.senderReports[ssrc] = reports
		c.reportOrder[ssrc] = nil
	}

	if _, exists := reports[ntpShort]; !exists {
		c.reportOrder[ssrc] = append(
			c.reportOrder[ssrc],
			ntpShort,
		)
	}

	reports[ntpShort] = capturedAt

	order := c.reportOrder[ssrc]

	for len(order) > maxStoredSenderReports {
		oldest := order[0]
		order = order[1:]

		delete(reports, oldest)
	}

	c.reportOrder[ssrc] = order
}
