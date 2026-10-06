package emodel

import (
	"math"
	"testing"

	"github.com/alirezarajaee/callquality-ai/app/internal/features"
)

func TestDefaultG711Config(t *testing.T) {
	config := DefaultG711Config()

	if config.Ro != 94.2 {
		t.Fatalf(
			"Ro mismatch: got %.6f want 94.2",
			config.Ro,
		)
	}

	if config.Is != 0 {
		t.Fatalf(
			"Is mismatch: got %.6f want 0",
			config.Is,
		)
	}

	if config.A != 0 {
		t.Fatalf(
			"A mismatch: got %.6f want 0",
			config.A,
		)
	}

	if config.Ie != 0 {
		t.Fatalf(
			"Ie mismatch: got %.6f want 0",
			config.Ie,
		)
	}

	if config.Bpl != 25.1 {
		t.Fatalf(
			"Bpl mismatch: got %.6f want 25.1",
			config.Bpl,
		)
	}

	if config.BurstR != 1 {
		t.Fatalf(
			"BurstR mismatch: got %.6f want 1",
			config.BurstR,
		)
	}
}

func TestDelayImpairment(t *testing.T) {
	tests := []struct {
		name  string
		delay float64
		want  float64
	}{
		{
			name:  "zero",
			delay: 0,
			want:  0,
		},
		{
			name:  "50ms",
			delay: 50,
			want:  1.2,
		},
		{
			name:  "100ms",
			delay: 100,
			want:  2.4,
		},
		{
			name:  "threshold",
			delay: 177.3,
			want:  4.2552,
		},
		{
			name:  "250ms",
			delay: 250,
			want:  13.997,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DelayImpairment(tt.delay)

			if math.Abs(got-tt.want) > 1e-9 {
				t.Fatalf(
					"delay impairment mismatch: got %.12f want %.12f",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestEffectiveEquipmentImpairment(t *testing.T) {
	t.Run("zero loss", func(t *testing.T) {
		got := EffectiveEquipmentImpairment(
			0,
			25.1,
			0,
			1,
		)

		if math.Abs(got) > 1e-12 {
			t.Fatalf(
				"expected zero Ie-eff, got %.12f",
				got,
			)
		}
	})

	t.Run("one percent loss", func(t *testing.T) {
		got := EffectiveEquipmentImpairment(
			0,
			25.1,
			1,
			1,
		)

		want := (95.0 * 1.0) /
			(1.0 + 25.1)

		if math.Abs(got-want) > 1e-12 {
			t.Fatalf(
				"Ie-eff mismatch: got %.12f want %.12f",
				got,
				want,
			)
		}
	})

	t.Run("zero Bpl", func(t *testing.T) {
		got := EffectiveEquipmentImpairment(
			0,
			0,
			10,
			1,
		)

		if got != 0 {
			t.Fatalf(
				"expected original Ie, got %.12f",
				got,
			)
		}
	})
}

func TestMOSFromR(t *testing.T) {
	tests := []struct {
		name string
		r    float64
		want float64
	}{
		{
			name: "negative",
			r:    -10,
			want: 1,
		},
		{
			name: "zero",
			r:    0,
			want: 1,
		},
		{
			name: "R 100",
			r:    100,
			want: 4.5,
		},
		{
			name: "above 100",
			r:    120,
			want: 4.5,
		},
		{
			name: "R 94.2",
			r:    94.2,
			want: 4.427798584,
		},
		{
			name: "R 88.1601532567",
			r:    88.16015325670497,
			want: 4.29136087267211,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MOSFromR(tt.r)

			if math.Abs(got-tt.want) > 1e-9 {
				t.Fatalf(
					"MOS mismatch: got %.12f want %.12f",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestEstimatePerfectNetwork(t *testing.T) {
	config := DefaultG711Config()

	result, err := Estimate(
		config,
		Inputs{
			OneWayDelayMs:     0,
			DelayKnown:        true,
			PacketLossPercent: 0,
			LossKnown:         true,
		},
	)

	if err != nil {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	if math.Abs(result.RFactor-94.2) > 1e-12 {
		t.Fatalf(
			"R mismatch: got %.12f want 94.2",
			result.RFactor,
		)
	}

	if math.Abs(
		result.MOSCQE-4.427798584,
	) > 1e-9 {
		t.Fatalf(
			"MOS mismatch: got %.12f",
			result.MOSCQE,
		)
	}

	if result.Id != 0 {
		t.Fatalf(
			"expected zero Id, got %.12f",
			result.Id,
		)
	}

	if result.IeEff != 0 {
		t.Fatalf(
			"expected zero Ie-eff, got %.12f",
			result.IeEff,
		)
	}
}

func TestEstimateWithDelayAndLoss(t *testing.T) {
	config := DefaultG711Config()

	result, err := Estimate(
		config,
		Inputs{
			OneWayDelayMs:     100,
			DelayKnown:        true,
			PacketLossPercent: 1,
			LossKnown:         true,
		},
	)

	if err != nil {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	expectedId := 2.4

	expectedIeEff :=
		(95.0 * 1.0) /
			(1.0 + 25.1)

	expectedR :=
		94.2 -
			expectedId -
			expectedIeEff

	if math.Abs(result.Id-expectedId) > 1e-12 {
		t.Fatalf(
			"Id mismatch: got %.12f want %.12f",
			result.Id,
			expectedId,
		)
	}

	if math.Abs(result.IeEff-expectedIeEff) > 1e-12 {
		t.Fatalf(
			"Ie-eff mismatch: got %.12f want %.12f",
			result.IeEff,
			expectedIeEff,
		)
	}

	if math.Abs(result.RFactor-expectedR) > 1e-12 {
		t.Fatalf(
			"R mismatch: got %.12f want %.12f",
			result.RFactor,
			expectedR,
		)
	}

	if result.MOSCQE <= 1 ||
		result.MOSCQE >= 4.5 {
		t.Fatalf(
			"unexpected MOS %.12f",
			result.MOSCQE,
		)
	}
}

func TestEstimateFromStreamFeaturesUsesRTTHalfProxy(t *testing.T) {
	config := DefaultG711Config()

	input := features.StreamFeatures{
		CallID:      "call-001",
		SSRC:        0x11223344,
		PacketCount: 1000,

		RTPLossPercent: 1.0,

		HasRTCP:                1,
		RTCPLossAveragePercent: 2.0,

		RTTAvailableAverage: 1,
		RTTAverageMs:        200,
	}

	result, err := EstimateFromStreamFeatures(
		config,
		input,
	)

	if err != nil {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	if !result.DelayKnown {
		t.Fatal("expected delay to be known")
	}

	if result.DelaySource != "passive_rtt_half_proxy" {
		t.Fatalf(
			"delay source mismatch: got %q",
			result.DelaySource,
		)
	}

	if math.Abs(result.OneWayDelayMs-100) > 1e-12 {
		t.Fatalf(
			"one-way delay proxy mismatch: got %.12f",
			result.OneWayDelayMs,
		)
	}

	if result.LossSource != "rtcp_average" {
		t.Fatalf(
			"loss source mismatch: got %q",
			result.LossSource,
		)
	}

	if math.Abs(result.PacketLossPercent-2) > 1e-12 {
		t.Fatalf(
			"loss mismatch: got %.12f want 2",
			result.PacketLossPercent,
		)
	}
}

func TestEstimateFromStreamFeaturesWithoutRTCP(t *testing.T) {
	config := DefaultG711Config()

	input := features.StreamFeatures{
		CallID:         "call-no-rtcp",
		SSRC:           0x12345678,
		PacketCount:    500,
		RTPLossPercent: 0.5,
	}

	result, err := EstimateFromStreamFeatures(
		config,
		input,
	)

	if err != nil {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	if result.DelayKnown {
		t.Fatal("expected delay to be unavailable")
	}

	if result.DelaySource != "one_way_delay_input" {
		t.Fatalf(
			"unexpected delay source: %q",
			result.DelaySource,
		)
	}

	if result.LossSource != "rtp" {
		t.Fatalf(
			"unexpected loss source: %q",
			result.LossSource,
		)
	}

	if math.Abs(result.PacketLossPercent-0.5) > 1e-12 {
		t.Fatalf(
			"loss mismatch: got %.12f",
			result.PacketLossPercent,
		)
	}
}

func TestEstimateRejectsInvalidConfig(t *testing.T) {
	config := DefaultG711Config()

	config.Ie = 95

	_, err := Estimate(
		config,
		Inputs{},
	)

	if err == nil {
		t.Fatal("expected invalid Ie error")
	}
}

func TestEstimateClampsLoss(t *testing.T) {
	config := DefaultG711Config()

	result, err := Estimate(
		config,
		Inputs{
			DelayKnown:        true,
			LossKnown:         true,
			PacketLossPercent: 150,
		},
	)

	if err != nil {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	if result.PacketLossPercent != 100 {
		t.Fatalf(
			"expected loss to clamp at 100, got %.12f",
			result.PacketLossPercent,
		)
	}
}
