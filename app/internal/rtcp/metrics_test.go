package rtcp

import (
	"math"
	"testing"
)

func TestFractionLostConversion(t *testing.T) {
	tests := []struct {
		name    string
		input   uint8
		wantRat float64
		wantPct float64
	}{
		{
			name:    "zero",
			input:   0,
			wantRat: 0,
			wantPct: 0,
		},
		{
			name:    "half",
			input:   128,
			wantRat: 0.5,
			wantPct: 50,
		},
		{
			name:    "quarter",
			input:   64,
			wantRat: 0.25,
			wantPct: 25,
		},
		{
			name:    "maximum",
			input:   255,
			wantRat: 255.0 / 256.0,
			wantPct: 255.0 / 256.0 * 100.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRatio := FractionLostRatio(tt.input)
			gotPercent := FractionLostPercent(tt.input)

			if math.Abs(gotRatio-tt.wantRat) > 1e-12 {
				t.Fatalf(
					"ratio mismatch: got %.12f want %.12f",
					gotRatio,
					tt.wantRat,
				)
			}

			if math.Abs(gotPercent-tt.wantPct) > 1e-10 {
				t.Fatalf(
					"percent mismatch: got %.12f want %.12f",
					gotPercent,
					tt.wantPct,
				)
			}
		})
	}
}

func TestJitterMilliseconds(t *testing.T) {
	tests := []struct {
		name      string
		jitter    uint32
		clockRate uint32
		wantMs    float64
	}{
		{
			name:      "8kHz",
			jitter:    80,
			clockRate: 8000,
			wantMs:    10,
		},
		{
			name:      "48kHz",
			jitter:    480,
			clockRate: 48000,
			wantMs:    10,
		},
		{
			name:      "zero clock rate",
			jitter:    480,
			clockRate: 0,
			wantMs:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := JitterMilliseconds(
				tt.jitter,
				tt.clockRate,
			)

			if math.Abs(got-tt.wantMs) > 1e-12 {
				t.Fatalf(
					"jitter mismatch: got %.12f want %.12f",
					got,
					tt.wantMs,
				)
			}
		})
	}
}

func TestDLSRSeconds(t *testing.T) {
	tests := []struct {
		name  string
		input uint32
		want  float64
	}{
		{
			name:  "zero",
			input: 0,
			want:  0,
		},
		{
			name:  "one second",
			input: 65536,
			want:  1,
		},
		{
			name:  "half second",
			input: 32768,
			want:  0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DLSRSeconds(tt.input)

			if math.Abs(got-tt.want) > 1e-12 {
				t.Fatalf(
					"DLSR mismatch: got %.12f want %.12f",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestNTPShort(t *testing.T) {
	const (
		ntpSeconds  = uint32(0x12345678)
		ntpFraction = uint32(0x9abcdef0)
	)

	got := NTPShort(
		ntpSeconds,
		ntpFraction,
	)

	want := uint32(0x56789abc)

	if got != want {
		t.Fatalf(
			"NTP short mismatch: got 0x%08x want 0x%08x",
			got,
			want,
		)
	}
}

func TestNTPShortSeconds(t *testing.T) {
	value := uint32(2<<16) | uint32(32768)

	got := NTPShortSeconds(value)
	want := 2.5

	if math.Abs(got-want) > 1e-12 {
		t.Fatalf(
			"NTP short seconds mismatch: got %.12f want %.12f",
			got,
			want,
		)
	}
}

func TestRoundTripTimeSeconds(t *testing.T) {
	t.Run("valid RTT", func(t *testing.T) {
		lsr := uint32(100 << 16)
		dlsr := uint32(1 << 16)
		arrival := uint32(103 << 16)

		got, ok := RoundTripTimeSeconds(
			arrival,
			lsr,
			dlsr,
		)

		if !ok {
			t.Fatal("expected valid RTT")
		}

		want := 2.0

		if math.Abs(got-want) > 1e-12 {
			t.Fatalf(
				"RTT mismatch: got %.12f want %.12f",
				got,
				want,
			)
		}
	})

	t.Run("missing LSR", func(t *testing.T) {
		got, ok := RoundTripTimeSeconds(
			200<<16,
			0,
			1<<16,
		)

		if ok {
			t.Fatal("expected invalid RTT")
		}

		if got != 0 {
			t.Fatalf(
				"expected zero RTT, got %.12f",
				got,
			)
		}
	})

	t.Run("DLSR exceeds elapsed time", func(t *testing.T) {
		got, ok := RoundTripTimeSeconds(
			101<<16,
			100<<16,
			2<<16,
		)

		if ok {
			t.Fatal("expected invalid RTT")
		}

		if got != 0 {
			t.Fatalf(
				"expected zero RTT, got %.12f",
				got,
			)
		}
	})
}

func TestReportBlockMetrics(t *testing.T) {
	block := ReportBlock{
		SSRC:                       0x11223344,
		FractionLost:               128,
		CumulativePacketsLost:      12,
		HighestSequenceNumber:      1000,
		Jitter:                     80,
		LastSenderReport:           0x56789abc,
		DelaySinceLastSenderReport: 32768,
	}

	metrics := block.Metrics(8000)

	if math.Abs(metrics.FractionLostRatio-0.5) > 1e-12 {
		t.Fatalf(
			"fraction ratio mismatch: got %.12f",
			metrics.FractionLostRatio,
		)
	}

	if math.Abs(metrics.FractionLostPercent-50) > 1e-12 {
		t.Fatalf(
			"fraction percent mismatch: got %.12f",
			metrics.FractionLostPercent,
		)
	}

	if metrics.CumulativePacketsLost != 12 {
		t.Fatalf(
			"cumulative loss mismatch: got %d",
			metrics.CumulativePacketsLost,
		)
	}

	if !metrics.JitterAvailable {
		t.Fatal("expected jitter to be available")
	}

	if math.Abs(metrics.JitterMilliseconds-10) > 1e-12 {
		t.Fatalf(
			"jitter mismatch: got %.12f",
			metrics.JitterMilliseconds,
		)
	}

	if math.Abs(metrics.DelaySinceLastSRSeconds-0.5) > 1e-12 {
		t.Fatalf(
			"DLSR mismatch: got %.12f",
			metrics.DelaySinceLastSRSeconds,
		)
	}

	if err := ValidateReportMetrics(metrics); err != nil {
		t.Fatalf(
			"unexpected validation error: %v",
			err,
		)
	}
}

func TestReportBlockMetricsWithoutClockRate(t *testing.T) {
	block := ReportBlock{
		FractionLost:               64,
		Jitter:                     100,
		DelaySinceLastSenderReport: 0,
	}

	metrics := block.Metrics(0)

	if metrics.JitterAvailable {
		t.Fatal("expected jitter to be unavailable")
	}

	if metrics.JitterMilliseconds != 0 {
		t.Fatalf(
			"expected zero jitter milliseconds, got %.12f",
			metrics.JitterMilliseconds,
		)
	}
}