package rtcp

import "fmt"

// ReportMetrics contains normalized quality metrics derived from
// an RTCP reception report block.
type ReportMetrics struct {
	FractionLostRatio   float64
	FractionLostPercent float64

	CumulativePacketsLost int32

	JitterTimestampUnits uint32
	JitterMilliseconds    float64
	JitterAvailable      bool

	LastSenderReport           uint32
	DelaySinceLastSenderReport uint32
	DelaySinceLastSRSeconds    float64
}

// Metrics converts an RTCP report block into normalized metrics.
//
// clockRate is the RTP media clock rate, for example:
//   - PCMU/PCMA: 8000 Hz
//   - Opus: commonly 48000 Hz
func (b ReportBlock) Metrics(clockRate uint32) ReportMetrics {
	result := ReportMetrics{
		FractionLostRatio:        FractionLostRatio(b.FractionLost),
		FractionLostPercent:      FractionLostPercent(b.FractionLost),
		CumulativePacketsLost:    b.CumulativePacketsLost,
		JitterTimestampUnits:     b.Jitter,
		JitterMilliseconds:       0,
		JitterAvailable:          clockRate > 0,
		LastSenderReport:         b.LastSenderReport,
		DelaySinceLastSenderReport: b.DelaySinceLastSenderReport,
		DelaySinceLastSRSeconds:  DLSRSeconds(b.DelaySinceLastSenderReport),
	}

	if clockRate > 0 {
		result.JitterMilliseconds = JitterMilliseconds(
			b.Jitter,
			clockRate,
		)
	}

	return result
}

// FractionLostRatio converts the RTCP 8-bit fraction-lost field
// into a ratio in the range [0, 1].
func FractionLostRatio(value uint8) float64 {
	return float64(value) / 256.0
}

// FractionLostPercent converts the RTCP 8-bit fraction-lost field
// into a percentage in the range [0, 100).
func FractionLostPercent(value uint8) float64 {
	return FractionLostRatio(value) * 100.0
}

// JitterMilliseconds converts RTCP interarrival jitter from RTP
// timestamp units into milliseconds.
func JitterMilliseconds(jitter uint32, clockRate uint32) float64 {
	if clockRate == 0 {
		return 0
	}

	return float64(jitter) * 1000.0 / float64(clockRate)
}

// DLSRSeconds converts Delay Since Last Sender Report from
// 1/65536-second units into seconds.
func DLSRSeconds(value uint32) float64 {
	return float64(value) / 65536.0
}

// NTPShort converts an NTP timestamp represented by its 32-bit
// seconds and 32-bit fractional fields into the 32-bit LSR format
// used by RTCP reception reports.
//
// RFC 3550 defines LSR as the middle 32 bits of the 64-bit NTP
// timestamp:
//   - lower 16 bits of NTP seconds
//   - upper 16 bits of NTP fraction.
func NTPShort(ntpSeconds uint32, ntpFraction uint32) uint32 {
	return (ntpSeconds << 16) | (ntpFraction >> 16)
}

// NTPShortSeconds converts a 32-bit NTP short-format timestamp
// into fractional seconds.
func NTPShortSeconds(value uint32) float64 {
	wholeSeconds := value >> 16
	fraction := value & 0xffff

	return float64(wholeSeconds) +
		float64(fraction)/65536.0
}

// RoundTripTimeSeconds calculates RTCP round-trip time from:
//
//   RTT = A - LSR - DLSR
//
// where A is the reception time of the corresponding report block,
// expressed in the same 16.16 short-NTP format as LSR.
//
// The calculation returns false when the inputs cannot represent
// a sensible non-negative RTT.
func RoundTripTimeSeconds(
	arrivalShortNTP uint32,
	lastSenderReport uint32,
	delaySinceLastSenderReport uint32,
) (float64, bool) {
	if lastSenderReport == 0 {
		return 0, false
	}

	elapsed := uint32(arrivalShortNTP - lastSenderReport)

	// A valid RTT should not be negative. This also rejects values
	// that indicate an implausible wrap/ordering problem.
	if elapsed < delaySinceLastSenderReport {
		return 0, false
	}

	rttUnits := elapsed - delaySinceLastSenderReport

	// RTCP short-NTP values use 16 bits for the integer part.
	// Treat a very large result as invalid rather than reporting
	// an obviously unrealistic RTT.
	if rttUnits > 0x7fffffff {
		return 0, false
	}

	return float64(rttUnits) / 65536.0, true
}

// ValidateReportMetrics performs basic sanity validation on a
// normalized RTCP report.
func ValidateReportMetrics(metrics ReportMetrics) error {
	if metrics.FractionLostRatio < 0 ||
		metrics.FractionLostRatio > 1 {
		return fmt.Errorf(
			"invalid fraction lost ratio %.6f",
			metrics.FractionLostRatio,
		)
	}

	if metrics.FractionLostPercent < 0 ||
		metrics.FractionLostPercent > 100 {
		return fmt.Errorf(
			"invalid fraction lost percent %.6f",
			metrics.FractionLostPercent,
		)
	}

	if metrics.JitterAvailable && metrics.JitterMilliseconds < 0 {
		return fmt.Errorf(
			"invalid jitter %.6f ms",
			metrics.JitterMilliseconds,
		)
	}

	if metrics.DelaySinceLastSRSeconds < 0 {
		return fmt.Errorf(
			"invalid DLSR %.6f seconds",
			metrics.DelaySinceLastSRSeconds,
		)
	}

	return nil
}