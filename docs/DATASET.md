# Synthetic Dataset

CallQuality AI supports two synthetic dataset profiles.

## Legacy profile

The `legacy` profile preserves the original seven scenarios and their historical parameter schedule. It remains the default so the existing reproduction workflow stays stable.

## V4 research profile

The `v4` profile is designed for a stronger ML benchmark.

It keeps the same seven impairment families but introduces:

- five severity bands: mild, moderate, degraded, severe, extreme
- wider impairment ranges
- randomized parameter values within each band
- a secondary impairment for every non-clean scenario
- multi-impairment conditions at higher severity
- deterministic generation from a supplied seed
- manifest metadata describing the recipe used for each capture

The intention is to reduce simple scenario-to-label shortcuts and expose models to a broader range of combinations.

### Generate V4

Use the clean baseline capture:

```bat
go run ./cmd/datasetgen -profile v4 -input "..\\samples\\synthetic-clean-v2.pcap" -output-dir "..\\samples\\synthetic-dataset-v4" -samples-per-scenario 100 -seed 20261001
```

With seven scenario families and 100 samples per scenario, the generator will attempt to produce:

- 700 captures
- about 1400 media-stream records
- `dataset.csv`
- `manifest.csv`

Always use the actual generator output to verify the final record count.

### Research interpretation

`target_quality_level` remains the stream-level target produced by the current CallQuality AI engineering quality model. It is a synthetic engineering surrogate, not independently collected subjective human MOS ground truth.

The `scenario` field is metadata and must not be used as a model input.

For model evaluation, split by `sample_id` so both media streams of one capture remain in the same split.

Even with V4, real PCAP captures and independently obtained quality labels are required for real-world validation.
