package ml

import (
	"math"
	"testing"

	"github.com/alirezarajaee/callquality-ai/app/internal/export"
)

func TestLoadEmbeddedModel(t *testing.T) {
	model, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded failed: %v", err)
	}

	if len(model.artifact.Trees) != 700 {
		t.Fatalf("tree count mismatch: got %d want 700", len(model.artifact.Trees))
	}

	if len(model.artifact.FeatureNames) != 29 {
		t.Fatalf("feature count mismatch: got %d want 29", len(model.artifact.FeatureNames))
	}

	wantClasses := []string{"critical", "fair", "good", "poor"}
	if len(model.artifact.Classes) != len(wantClasses) {
		t.Fatalf("class count mismatch: got %d want %d", len(model.artifact.Classes), len(wantClasses))
	}

	for index, want := range wantClasses {
		if model.artifact.Classes[index] != want {
			t.Fatalf("class %d mismatch: got %q want %q", index, model.artifact.Classes[index], want)
		}
	}
}

func TestPredictVectorDeterministic(t *testing.T) {
	model, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded failed: %v", err)
	}

	vector := make([]float64, len(model.artifact.FeatureNames))
	vector[2] = 8000
	vector[3] = 1
	vector[4] = 200
	vector[5] = 1100
	vector[6] = 50
	vector[7] = 50
	vector[10] = 50
	vector[11] = 0
	vector[12] = 0
	vector[13] = 0
	vector[14] = 0
	vector[15] = 0
	vector[16] = 1
	vector[17] = 4.44
	vector[18] = 1
	vector[19] = 1
	vector[20] = 0
	vector[21] = 0
	vector[22] = 0
	vector[23] = 4.5
	vector[24] = 4.5
	vector[25] = 150
	vector[26] = 150
	vector[27] = 1
	vector[28] = 1

	first, err := model.PredictVector(vector)
	if err != nil {
		t.Fatalf("first prediction failed: %v", err)
	}

	second, err := model.PredictVector(vector)
	if err != nil {
		t.Fatalf("second prediction failed: %v", err)
	}

	if first.PredictedClass != second.PredictedClass {
		t.Fatalf("prediction is not deterministic: %q vs %q", first.PredictedClass, second.PredictedClass)
	}

	if !math.IsNaN(first.MaxProbability) && (first.MaxProbability < 0 || first.MaxProbability > 1) {
		t.Fatalf("invalid max probability: %v", first.MaxProbability)
	}

	probabilitySum := 0.0
	for _, item := range first.ClassProbabilities {
		probabilitySum += item.Value
	}

	if math.Abs(probabilitySum-1) > 1e-9 {
		t.Fatalf("probability sum mismatch: got %.12f", probabilitySum)
	}
}

func TestVectorFromRecordUsesMediansForUnavailableMeasurements(t *testing.T) {
	model, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded failed: %v", err)
	}

	record := export.Record{
		MediaIndex:      0,
		PayloadType:     0,
		ClockRate:       8000,
		CodecChannels:   1,
		SetupDurationMs: 200,
		CallDurationMs:  1100,
		PacketCount:     50,
		UniquePackets:   50,
		ExpectedPackets: 50,
		Codec:           "PCMU",
		Direction:       "sendrecv",
	}

	vector, err := model.VectorFromRecord(record)
	if err != nil {
		t.Fatalf("VectorFromRecord failed: %v", err)
	}

	if len(vector) != 29 {
		t.Fatalf("vector length mismatch: got %d want 29", len(vector))
	}

	for index, featureName := range model.artifact.FeatureNames {
		if featureName == "rtp_jitter_ms" {
			want := model.artifact.NumericMedians[featureName]
			if vector[index] != want {
				t.Fatalf("median fill mismatch for %s: got %v want %v", featureName, vector[index], want)
			}
		}
	}
}

func TestPredictRecordCleanSyntheticStream(t *testing.T) {
	model, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded failed: %v", err)
	}

	record := export.Record{
		MediaIndex:                 0,
		PayloadType:                0,
		Codec:                      "PCMU",
		ClockRate:                  8000,
		CodecChannels:              1,
		Direction:                  "sendrecv",
		SetupDurationMs:            200,
		CallDurationMs:             1100,
		PacketCount:                50,
		UniquePackets:              50,
		DuplicatePackets:           0,
		OutOfOrderPackets:          0,
		ExpectedPackets:            50,
		LostPackets:                0,
		RTPLossPercent:             0,
		LossPercent:                0,
		ReorderingPercent:          0,
		DuplicatePercent:           0,
		RTPLossAvailable:           true,
		RTPJitterMs:                floatPtr(4.44),
		RTCPAvailable:              true,
		RTCPObservationCount:       1,
		LatestFractionLostPercent:  floatPtr(0),
		AverageFractionLostPercent: floatPtr(0),
		LatestCumulativeLost:       int32Ptr(0),
		LatestJitterMs:             floatPtr(4.5),
		AverageJitterMs:            floatPtr(4.5),
		AveragePassiveRTTMs:        floatPtr(150),
		LatestPassiveRTTMs:         floatPtr(150),
	}

	prediction, err := model.PredictRecord(record)
	if err != nil {
		t.Fatalf("PredictRecord failed: %v", err)
	}

	if prediction.PredictedClass != "good" {
		t.Fatalf("unexpected synthetic clean prediction: got %q want good", prediction.PredictedClass)
	}
}

func floatPtr(value float64) *float64 {
	return &value
}

func int32Ptr(value int32) *int32 {
	return &value
}
