package rtp

import (
	"fmt"
	"time"
)

type JitterCalculator struct {
	initialized bool

	clockRate uint32

	previousTimestamp uint32
	previousArrival   time.Time

	previousTransit float64
	jitter          float64
}

func NewJitterCalculator(clockRate uint32) (*JitterCalculator, error) {
	if clockRate == 0 {
		return nil, fmt.Errorf("RTP clock rate must be greater than zero")
	}

	return &JitterCalculator{
		clockRate: clockRate,
	}, nil
}

func (j *JitterCalculator) Add(
	rtpTimestamp uint32,
	arrival time.Time,
) {
	if !j.initialized {
		j.initialized = true

		j.previousTimestamp = rtpTimestamp
		j.previousArrival = arrival

		j.previousTransit = 0
		j.jitter = 0

		return
	}

	arrivalDelta := arrival.Sub(j.previousArrival)

	arrivalUnits :=
		float64(arrivalDelta) *
			float64(j.clockRate) /
			float64(time.Second)

	timestampDelta := rtpTimestampDelta(
		rtpTimestamp,
		j.previousTimestamp,
	)

	transit := arrivalUnits -
		float64(timestampDelta)

	d := transit - j.previousTransit

	if d < 0 {
		d = -d
	}

	j.jitter +=
		(d - j.jitter) / 16.0

	j.previousTransit = transit
	j.previousTimestamp = rtpTimestamp
	j.previousArrival = arrival
}

func (j *JitterCalculator) Value() float64 {
	return j.jitter
}

func (j *JitterCalculator) Milliseconds() float64 {
	if j.clockRate == 0 {
		return 0
	}

	return j.jitter /
		float64(j.clockRate) *
		1000
}

func (j *JitterCalculator) ClockRate() uint32 {
	return j.clockRate
}

func rtpTimestampDelta(
	current uint32,
	previous uint32,
) int64 {
	delta := int64(current) -
		int64(previous)

	if delta > 2147483647 {
		delta -= 4294967296
	}

	if delta < -2147483648 {
		delta += 4294967296
	}

	return delta
}