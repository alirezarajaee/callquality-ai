# CallQuality AI — Native ML Inference

CallQuality AI includes a research-trained Random Forest classifier exported from Google Colab into a portable JSON artifact.

## Runtime architecture

```text
PCAP
  -> SIP/SDP + RTP/RTCP analysis
  -> unified media metrics
  -> feature export contract
  -> native Go ML preprocessing
  -> embedded Random Forest JSON
  -> engineering quality + E-model + diagnosis
  -> ML predicted quality class + uncalibrated class-vote probabilities
```

The production runtime does not require Python or scikit-learn.

## Model artifact

- Artifact: `app/internal/ml/callquality_ai_rf_v1.json`
- Model type: Random Forest classifier
- Trees: 700
- Transformed features: 29
- Classes: `critical`, `fair`, `good`, `poor`
- Artifact schema version: `1.0`

The artifact contains the trained tree structure, leaf class probabilities, feature order, and the numeric medians required for missing-value preprocessing.

## Training contract

The model target is `target_quality_level` from the V4 synthetic research dataset. This label is derived from the CallQuality AI engineering quality model and is not human subjective MOS ground truth.

The model input excludes downstream outputs such as:

- `quality_score`
- `quality_level`
- `r_factor`
- `mos`
- diagnosis outputs

Capture identifiers such as `sample_id`, `call_id`, `stream_id`, `ssrc`, and `scenario` are also excluded from model input.

## Integrated analysis

The `analyze` command now produces the engineering analysis and ML prediction in one run.

Example:

```text
callquality analyze capture.pcap

PCAP / signaling / media analysis
  -> Engineering score
  -> E-model / MOS
  -> Rule-based diagnosis
  -> Native Random Forest prediction
```

The standalone `predict` command remains available for ML-focused output.

The Random Forest values displayed by the CLI are **uncalibrated class-vote probabilities**. They should not be interpreted as calibrated confidence intervals or empirical probabilities.

## Verification

The portable model was compared against the original scikit-learn Random Forest on 250 transformed feature vectors. The verification artifact records 250/250 matching predictions and exact probability parity for those samples.

The verification metadata is stored at:

`research/models/callquality_ai_rf_v1_verification.json`


## HTTP API integration

The local HTTP API consumes the same Go analysis pipeline as the CLI. API clients therefore
receive engineering analysis and native ML inference from the same feature-extraction path.

The API returns ML class-vote values as uncalibrated Random Forest probabilities. It does not
claim calibrated confidence or subjective MOS accuracy.
