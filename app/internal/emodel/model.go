package emodel

import (
	"fmt"
	"math"

	"github.com/alirezarajaee/callquality-ai/app/internal/features"
)

// ModelVersion identifies the E-model baseline implementation.
const ModelVersion = "G107-NB-Network-Baseline-1.0"

// Config contains the E-model parameters used by this project.
//
// The defaults intentionally represent a simplified narrowband
// network-planning baseline rather than a full terminal/acoustic
// implementation of every G.107 parameter.
type Config struct {
	// Basic transmission rating factor.
	Ro float64

	// Simultaneous impairment factor.
	Is float64

	// Advantage factor.
	A float64

	// Codec/equipment impairment factor.
	Ie float64

	// Packet-loss robustness factor.
	Bpl float64

	// Burst ratio.
	BurstR float64
}

// DefaultG711Config returns the project baseline for a G.711-like
// narrowband network analysis.
//
// The values for Ie and Bpl are planning assumptions for the baseline
// and are intentionally configurable rather than hard-coded into the
// calculation.
func DefaultG711Config() Config {
	return Config{
		Ro:     94.2,
		Is:     0,
		A:      0,
		Ie:     0,
		Bpl:    25.1,
		BurstR: 1,
	}
}

// Inputs contains the network measurements supplied to the E-model.
type Inputs struct {
	OneWayDelayMs float64
	DelayKnown    bool

	PacketLossPercent float64
	LossKnown         bool
}

// Result contains the calculated E-model baseline.
type Result struct {
	ModelVersion string

	RFactor float64
	MOSCQE  float64

	Id    float64
	IeEff float64

	OneWayDelayMs     float64
	PacketLossPercent float64

	DelayKnown bool
	LossKnown  bool

	DelaySource string
	LossSource  string
}

// Estimate calculates the simplified narrowband network E-model
// baseline:
//
//	R = Ro - Is - Id - IeEff + A
//
// Id uses the commonly used delay impairment approximation:
//
//	Id = 0.024*T + 0.11*(T-177.3)*H(T-177.3)
//
// where T is one-way delay in milliseconds.
//
// IeEff uses the packet-loss impairment relationship:
//
//	IeEff = Ie + (95-Ie)*Ppl/(Ppl/BurstR + Bpl)
//
// Ppl is expressed as a percentage.
func Estimate(
	config Config,
	input Inputs,
) (Result, error) {
	if err := validateConfig(config); err != nil {
		return Result{}, err
	}

	cleanDelay := sanitizeNonNegative(
		input.OneWayDelayMs,
	)

	cleanLoss := sanitizeNonNegative(
		input.PacketLossPercent,
	)

	if cleanLoss > 100 {
		cleanLoss = 100
	}

	id := 0.0
	if input.DelayKnown {
		id = DelayImpairment(cleanDelay)
	}

	ieEff := EffectiveEquipmentImpairment(
		config.Ie,
		config.Bpl,
		cleanLoss,
		config.BurstR,
	)

	r := config.Ro -
		config.Is -
		id -
		ieEff +
		config.A

	mos := MOSFromR(r)

	return Result{
		ModelVersion: ModelVersion,

		RFactor: r,
		MOSCQE:  mos,

		Id:    id,
		IeEff: ieEff,

		OneWayDelayMs:     cleanDelay,
		PacketLossPercent: cleanLoss,

		DelayKnown: input.DelayKnown,
		LossKnown:  input.LossKnown,

		DelaySource: "one_way_delay_input",
		LossSource:  "packet_loss_input",
	}, nil
}

// EstimateFromStreamFeatures adapts our existing feature vector into
// the E-model baseline.
//
// Because our current feature vector contains passive RTT rather than
// direct one-way mouth-to-ear delay, RTT/2 is used only as an explicitly
// labeled network-delay proxy.
//
// This is a project-level approximation and should not be described as
// a full G.107 mouth-to-ear delay measurement.
func EstimateFromStreamFeatures(
	config Config,
	input features.StreamFeatures,
) (Result, error) {
	modelInput := Inputs{
		DelayKnown: false,
		LossKnown:  input.PacketCount > 0,
	}

	if input.PacketCount > 0 {
		modelInput.PacketLossPercent =
			sanitizeNonNegative(
				input.RTPLossPercent,
			)

		if input.HasRTCP > 0 &&
			input.RTCPLossAveragePercent >
				modelInput.PacketLossPercent {

			modelInput.PacketLossPercent =
				sanitizeNonNegative(
					input.RTCPLossAveragePercent,
				)
		}
	}

	if input.RTTAvailableAverage > 0 {
		modelInput.OneWayDelayMs =
			sanitizeNonNegative(
				input.RTTAverageMs / 2,
			)

		modelInput.DelayKnown = true
	} else if input.RTTAvailableLatest > 0 {
		modelInput.OneWayDelayMs =
			sanitizeNonNegative(
				input.RTTLatestMs / 2,
			)

		modelInput.DelayKnown = true
	}

	result, err := Estimate(
		config,
		modelInput,
	)

	if err != nil {
		return Result{}, err
	}

	if result.DelayKnown {
		result.DelaySource =
			"passive_rtt_half_proxy"
	}

	if result.LossKnown {
		if input.HasRTCP > 0 &&
			input.RTCPLossAveragePercent >
				input.RTPLossPercent {

			result.LossSource = "rtcp_average"
		} else {
			result.LossSource = "rtp"
		}
	} else {
		result.LossSource = "unavailable"
	}

	return result, nil
}

// DelayImpairment calculates the delay impairment term Id.
//
// T is in milliseconds.
func DelayImpairment(
	oneWayDelayMs float64,
) float64 {
	d := sanitizeNonNegative(oneWayDelayMs)

	result := 0.024 * d

	if d > 177.3 {
		result += 0.11 * (d - 177.3)
	}

	return result
}

// EffectiveEquipmentImpairment calculates Ie-eff.
//
// packetLossPercent is expressed as 0..100.
func EffectiveEquipmentImpairment(
	ie float64,
	bpl float64,
	packetLossPercent float64,
	burstRatio float64,
) float64 {
	ppl := sanitizeNonNegative(packetLossPercent)

	if ppl > 100 {
		ppl = 100
	}

	if burstRatio <= 0 || bpl <= 0 {
		return ie
	}

	denominator :=
		(ppl / burstRatio) +
			bpl

	if denominator <= 0 {
		return ie
	}

	return ie +
		(95-ie)*
			ppl/
			denominator
}

// MOSFromR converts R into the conversational-quality MOS estimate
// defined by the E-model MOS conversion.
//
// The result is clamped to the conventional 1.0..4.5 interval.
func MOSFromR(
	r float64,
) float64 {
	if math.IsNaN(r) {
		return 1
	}

	if r <= 0 {
		return 1
	}

	if r >= 100 {
		return 4.5
	}

	mos :=
		1 +
			0.035*r +
			r*(r-60)*(100-r)*7e-6

	if mos < 1 {
		return 1
	}

	if mos > 4.5 {
		return 4.5
	}

	return mos
}

func validateConfig(
	config Config,
) error {
	if config.Ro < 0 {
		return fmt.Errorf(
			"invalid Ro %.6f",
			config.Ro,
		)
	}

	if config.Ie < 0 ||
		config.Ie >= 95 {
		return fmt.Errorf(
			"Ie must be in the range [0,95), got %.6f",
			config.Ie,
		)
	}

	if config.Bpl <= 0 {
		return fmt.Errorf(
			"Bpl must be greater than zero, got %.6f",
			config.Bpl,
		)
	}

	if config.BurstR <= 0 {
		return fmt.Errorf(
			"BurstR must be greater than zero, got %.6f",
			config.BurstR,
		)
	}

	return nil
}

func sanitizeNonNegative(
	value float64,
) float64 {
	if math.IsNaN(value) ||
		math.IsInf(value, 0) ||
		value < 0 {
		return 0
	}

	return value
}
