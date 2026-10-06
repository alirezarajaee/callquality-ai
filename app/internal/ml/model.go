package ml

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/alirezarajaee/callquality-ai/app/internal/export"
)

const (
	ArtifactSchemaVersion = "1.0"
	ModelArtifactVersion  = "v1"
)

//go:embed callquality_ai_rf_v1.json
var embeddedModel []byte

type treeArtifact struct {
	Feature           []int       `json:"feature"`
	Threshold         []float64   `json:"threshold"`
	Left              []int       `json:"left"`
	Right             []int       `json:"right"`
	LeafProbabilities [][]float64 `json:"leaf_probabilities"`
}

type artifact struct {
	ArtifactSchemaVersion string             `json:"artifact_schema_version"`
	ModelType             string             `json:"model_type"`
	Target                string             `json:"target"`
	Classes               []string           `json:"classes"`
	FeatureNames          []string           `json:"feature_names"`
	NumericFeatures       []string           `json:"numeric_features"`
	CategoricalFeatures   []string           `json:"categorical_features"`
	NumericMedians        map[string]float64 `json:"numeric_medians"`
	Trees                 []treeArtifact     `json:"trees"`
	NTrees                int                `json:"n_trees"`
}

// Model is a native Go Random Forest inference engine for the exported
// CallQuality AI model. It does not require Python or scikit-learn at runtime.
type Model struct {
	artifact artifact
}

// Prediction contains the predicted class and the Random Forest class vote
// probabilities. These are not calibrated probabilities.
type Prediction struct {
	ClassProbabilities []ClassProbability
	PredictedClass     string
	MaxProbability     float64
}

// ClassProbability contains a class label and its Random Forest probability.
type ClassProbability struct {
	Class string
	Value float64
}

// LoadEmbedded loads the repository-embedded production model artifact.
func LoadEmbedded() (*Model, error) {
	return load(embeddedModel)
}

func load(data []byte) (*Model, error) {
	var parsed artifact
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("decode model artifact: %w", err)
	}

	if err := validateArtifact(parsed); err != nil {
		return nil, err
	}

	return &Model{artifact: parsed}, nil
}

func validateArtifact(model artifact) error {
	if model.ArtifactSchemaVersion != ArtifactSchemaVersion {
		return fmt.Errorf(
			"unsupported artifact schema version %q",
			model.ArtifactSchemaVersion,
		)
	}

	if model.ModelType != "random_forest_classifier" {
		return fmt.Errorf("unsupported model type %q", model.ModelType)
	}

	if len(model.Classes) == 0 {
		return fmt.Errorf("model artifact contains no classes")
	}

	if len(model.FeatureNames) == 0 {
		return fmt.Errorf("model artifact contains no features")
	}

	if len(model.Trees) == 0 {
		return fmt.Errorf("model artifact contains no trees")
	}

	if model.NTrees != len(model.Trees) {
		return fmt.Errorf(
			"tree count mismatch: declared %d actual %d",
			model.NTrees,
			len(model.Trees),
		)
	}

	for treeIndex, tree := range model.Trees {
		nodeCount := len(tree.Feature)
		if nodeCount == 0 {
			return fmt.Errorf("tree %d contains no nodes", treeIndex)
		}

		if len(tree.Threshold) != nodeCount ||
			len(tree.Left) != nodeCount ||
			len(tree.Right) != nodeCount ||
			len(tree.LeafProbabilities) != nodeCount {
			return fmt.Errorf(
				"tree %d node arrays have inconsistent lengths",
				treeIndex,
			)
		}

		for nodeIndex := 0; nodeIndex < nodeCount; nodeIndex++ {
			left := tree.Left[nodeIndex]
			right := tree.Right[nodeIndex]
			featureIndex := tree.Feature[nodeIndex]
			isLeaf := left == -1 && right == -1

			if left == -1 || right == -1 {
				if !isLeaf {
					return fmt.Errorf(
						"tree %d node %d has only one leaf child marker",
						treeIndex,
						nodeIndex,
					)
				}
			} else {
				if left < 0 || left >= nodeCount || right < 0 || right >= nodeCount {
					return fmt.Errorf(
						"tree %d node %d has invalid child index",
						treeIndex,
						nodeIndex,
					)
				}
				if featureIndex < 0 || featureIndex >= len(model.FeatureNames) {
					return fmt.Errorf(
						"tree %d node %d has invalid feature index %d",
						treeIndex,
						nodeIndex,
						featureIndex,
					)
				}
			}

			probabilities := tree.LeafProbabilities[nodeIndex]
			if !isLeaf {
				continue
			}

			if len(probabilities) != len(model.Classes) {
				return fmt.Errorf(
					"tree %d leaf %d probability count mismatch",
					treeIndex,
					nodeIndex,
				)
			}

			sum := 0.0
			for _, value := range probabilities {
				if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
					return fmt.Errorf(
						"tree %d leaf %d contains invalid probability",
						treeIndex,
						nodeIndex,
					)
				}
				sum += value
			}

			if math.Abs(sum-1.0) > 1e-9 {
				return fmt.Errorf(
					"tree %d leaf %d probability sum %.12f is not 1",
					treeIndex,
					nodeIndex,
					sum,
				)
			}
		}
	}

	return nil
}

// PredictVector predicts from an already transformed feature vector.
func (model *Model) PredictVector(vector []float64) (Prediction, error) {
	if model == nil {
		return Prediction{}, fmt.Errorf("model is nil")
	}
	if len(vector) != len(model.artifact.FeatureNames) {
		return Prediction{}, fmt.Errorf(
			"feature vector length mismatch: got %d want %d",
			len(vector),
			len(model.artifact.FeatureNames),
		)
	}

	probabilities := make([]float64, len(model.artifact.Classes))

	for treeIndex, tree := range model.artifact.Trees {
		node := 0
		visited := 0

		for {
			visited++
			if visited > len(tree.Feature)+1 {
				return Prediction{}, fmt.Errorf(
					"tree %d traversal exceeded node bound",
					treeIndex,
				)
			}

			left := tree.Left[node]
			right := tree.Right[node]
			if left == -1 && right == -1 {
				for classIndex, probability := range tree.LeafProbabilities[node] {
					probabilities[classIndex] += probability
				}
				break
			}

			featureIndex := tree.Feature[node]
			if vector[featureIndex] <= tree.Threshold[node] {
				node = left
			} else {
				node = right
			}
		}
	}

	invTreeCount := 1.0 / float64(len(model.artifact.Trees))
	for index := range probabilities {
		probabilities[index] *= invTreeCount
	}

	bestIndex := 0
	for index := 1; index < len(probabilities); index++ {
		if probabilities[index] > probabilities[bestIndex] {
			bestIndex = index
		}
	}

	result := Prediction{
		PredictedClass:     model.artifact.Classes[bestIndex],
		MaxProbability:     probabilities[bestIndex],
		ClassProbabilities: make([]ClassProbability, len(probabilities)),
	}

	for index, value := range probabilities {
		result.ClassProbabilities[index] = ClassProbability{
			Class: model.artifact.Classes[index],
			Value: value,
		}
	}

	return result, nil
}

// PredictRecord applies the training preprocessing contract and predicts one
// exported media-stream record.
func (model *Model) PredictRecord(record export.Record) (Prediction, error) {
	vector, err := model.VectorFromRecord(record)
	if err != nil {
		return Prediction{}, err
	}
	return model.PredictVector(vector)
}

// VectorFromRecord converts one exported media-stream record into the exact
// transformed vector consumed by the Random Forest.
func (model *Model) VectorFromRecord(record export.Record) ([]float64, error) {
	if model == nil {
		return nil, fmt.Errorf("model is nil")
	}

	vector := make([]float64, len(model.artifact.FeatureNames))
	for index, featureName := range model.artifact.FeatureNames {
		value, found := model.numericRecordValue(record, featureName)
		if found {
			vector[index] = value
			continue
		}

		switch featureName {
		case "codec_PCMU":
			if strings.EqualFold(strings.TrimSpace(record.Codec), "PCMU") {
				vector[index] = 1
			}
		case "media_direction_sendrecv":
			if strings.EqualFold(strings.TrimSpace(record.Direction), "sendrecv") {
				vector[index] = 1
			}
		default:
			return nil, fmt.Errorf("unsupported model feature %q", featureName)
		}
	}

	return vector, nil
}

func (model *Model) numericRecordValue(record export.Record, featureName string) (float64, bool) {
	switch featureName {
	case "media_index":
		return float64(record.MediaIndex), true
	case "payload_type":
		return float64(record.PayloadType), true
	case "clock_rate":
		return float64(record.ClockRate), true
	case "codec_channels":
		return float64(record.CodecChannels), true
	case "setup_duration_ms":
		return record.SetupDurationMs, true
	case "call_duration_ms":
		return record.CallDurationMs, true
	case "packet_count":
		return float64(record.PacketCount), true
	case "unique_packets":
		return float64(record.UniquePackets), true
	case "duplicate_packets":
		return float64(record.DuplicatePackets), true
	case "out_of_order_packets":
		return float64(record.OutOfOrderPackets), true
	case "expected_packets":
		return float64(record.ExpectedPackets), true
	case "lost_packets":
		return float64(record.LostPackets), true
	case "rtp_loss_percent":
		return record.RTPLossPercent, true
	case "loss_percent":
		return record.LossPercent, true
	case "reordering_percent":
		return record.ReorderingPercent, true
	case "duplicate_percent":
		return record.DuplicatePercent, true
	case "rtp_loss_available":
		return boolFloat(record.RTPLossAvailable), true
	case "rtp_jitter_ms":
		return model.floatPointerValueOrMedian(featureName, record.RTPJitterMs), true
	case "rtcp_available":
		return boolFloat(record.RTCPAvailable), true
	case "rtcp_observation_count":
		return float64(record.RTCPObservationCount), true
	case "latest_fraction_lost_percent":
		return model.floatPointerValueOrMedian(featureName, record.LatestFractionLostPercent), true
	case "average_fraction_lost_percent":
		return model.floatPointerValueOrMedian(featureName, record.AverageFractionLostPercent), true
	case "latest_cumulative_lost":
		if record.LatestCumulativeLost == nil {
			return model.numericMedian(featureName), true
		}
		return float64(*record.LatestCumulativeLost), true
	case "latest_jitter_ms":
		return model.floatPointerValueOrMedian(featureName, record.LatestJitterMs), true
	case "average_jitter_ms":
		return model.floatPointerValueOrMedian(featureName, record.AverageJitterMs), true
	case "average_passive_rtt_ms":
		return model.floatPointerValueOrMedian(featureName, record.AveragePassiveRTTMs), true
	case "latest_passive_rtt_ms":
		return model.floatPointerValueOrMedian(featureName, record.LatestPassiveRTTMs), true
	default:
		return 0, false
	}
}

func (model *Model) floatPointerValueOrMedian(featureName string, value *float64) float64 {
	if value != nil {
		return *value
	}
	return model.numericMedian(featureName)
}

func (model *Model) numericMedian(featureName string) float64 {
	return model.artifact.NumericMedians[featureName]
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}
