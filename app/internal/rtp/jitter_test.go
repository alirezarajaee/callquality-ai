package rtp

import (
	"math"
	"testing"
	"time"
)

func TestJitterCalculatorStableStream(t *testing.T) {
	calculator, err := NewJitterCalculator(8000)
	if err != nil {
		t.Fatalf(
			"NewJitterCalculator() error = %v",
			err,
		)
	}

	baseTime := time.Unix(1700000000, 0)

	packets := []struct {
		timestamp uint32
		arrival   time.Time
	}{
		{
			timestamp: 0,
			arrival:   baseTime,
		},
		{
			timestamp: 160,
			arrival:   baseTime.Add(20 * time.Millisecond),
		},
		{
			timestamp: 320,
			arrival:   baseTime.Add(40 * time.Millisecond),
		},
		{
			timestamp: 480,
			arrival:   baseTime.Add(60 * time.Millisecond),
		},
	}

	for _, packet := range packets {
		calculator.Add(
			packet.timestamp,
			packet.arrival,
		)
	}

	if calculator.Value() > 0.0001 {
		t.Fatalf(
			"expected near-zero jitter, got %.6f RTP units",
			calculator.Value(),
		)
	}

	if calculator.Milliseconds() > 0.0001 {
		t.Fatalf(
			"expected near-zero jitter, got %.6f ms",
			calculator.Milliseconds(),
		)
	}
}

func TestJitterCalculatorTracksDelayVariation(t *testing.T) {
	calculator, err := NewJitterCalculator(8000)
	if err != nil {
		t.Fatalf(
			"NewJitterCalculator() error = %v",
			err,
		)
	}

	baseTime := time.Unix(1700000000, 0)

	packets := []struct {
		timestamp uint32
		arrival   time.Time
	}{
		{
			timestamp: 0,
			arrival:   baseTime,
		},
		{
			timestamp: 160,
			arrival:   baseTime.Add(20 * time.Millisecond),
		},
		{
			timestamp: 320,
			arrival:   baseTime.Add(60 * time.Millisecond),
		},
		{
			timestamp: 480,
			arrival:   baseTime.Add(80 * time.Millisecond),
		},
	}

	for _, packet := range packets {
		calculator.Add(
			packet.timestamp,
			packet.arrival,
		)
	}

	// The third packet introduces a 20 ms positive
	// transit variation.
	//
	// At 8000 Hz:
	// 20 ms = 160 RTP timestamp units.
	//
	// First update:
	// J = 0 + (160 - 0) / 16
	// J = 10
	//
	// The fourth packet then produces another transit
	// difference of 160 units in the opposite direction.
	//
	// Second update:
	// J = 10 + (160 - 10) / 16
	// J = 19.375
	expectedJitterUnits := 19.375

	if math.Abs(
		calculator.Value()-expectedJitterUnits,
	) > 0.0001 {
		t.Fatalf(
			"expected %.4f RTP units, got %.4f",
			expectedJitterUnits,
			calculator.Value(),
		)
	}

	expectedMilliseconds := 2.421875

	if math.Abs(
		calculator.Milliseconds()-expectedMilliseconds,
	) > 0.0001 {
		t.Fatalf(
			"expected %.6f ms, got %.6f ms",
			expectedMilliseconds,
			calculator.Milliseconds(),
		)
	}
}

func TestJitterCalculatorHandlesClockRate(t *testing.T) {
	calculator, err := NewJitterCalculator(48000)
	if err != nil {
		t.Fatalf(
			"NewJitterCalculator() error = %v",
			err,
		)
	}

	baseTime := time.Unix(1700000000, 0)

	calculator.Add(
		0,
		baseTime,
	)

	calculator.Add(
		960,
		baseTime.Add(20*time.Millisecond),
	)

	calculator.Add(
		1920,
		baseTime.Add(45*time.Millisecond),
	)

	expectedJitterUnits := 15.0

	if math.Abs(
		calculator.Value()-expectedJitterUnits,
	) > 0.0001 {
		t.Fatalf(
			"expected %.4f RTP units, got %.4f",
			expectedJitterUnits,
			calculator.Value(),
		)
	}

	expectedMilliseconds := 0.3125

	if math.Abs(
		calculator.Milliseconds()-expectedMilliseconds,
	) > 0.0001 {
		t.Fatalf(
			"expected %.4f ms, got %.4f ms",
			expectedMilliseconds,
			calculator.Milliseconds(),
		)
	}
}

func TestJitterCalculatorHandlesTimestampWrapAround(t *testing.T) {
	calculator, err := NewJitterCalculator(8000)
	if err != nil {
		t.Fatalf(
			"NewJitterCalculator() error = %v",
			err,
		)
	}

	baseTime := time.Unix(1700000000, 0)

	calculator.Add(
		4294967200,
		baseTime,
	)

	calculator.Add(
		64,
		baseTime.Add(20*time.Millisecond),
	)

	if calculator.Value() > 0.0001 {
		t.Fatalf(
			"expected near-zero jitter across timestamp wrap, got %.6f",
			calculator.Value(),
		)
	}
}

func TestJitterCalculatorRejectsZeroClockRate(t *testing.T) {
	_, err := NewJitterCalculator(0)

	if err == nil {
		t.Fatal(
			"expected zero clock rate to produce an error",
		)
	}
}

func TestJitterCalculatorInitialValue(t *testing.T) {
	calculator, err := NewJitterCalculator(8000)
	if err != nil {
		t.Fatalf(
			"NewJitterCalculator() error = %v",
			err,
		)
	}

	if calculator.Value() != 0 {
		t.Fatalf(
			"expected initial jitter 0, got %.6f",
			calculator.Value(),
		)
	}

	if calculator.Milliseconds() != 0 {
		t.Fatalf(
			"expected initial jitter 0 ms, got %.6f",
			calculator.Milliseconds(),
		)
	}
}