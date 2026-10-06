# CallQuality AI — Architecture

## 1. Architecture Overview

CallQuality AI is designed as a local-first system composed of four main layers:

1. VoIP Analysis Engine
2. ML Inference Layer
3. Diagnosis Layer
4. User Interface

The Research environment is intentionally separated from the runtime application.

High-level architecture:

PCAP
→ Protocol Analysis
→ Feature Extraction
→ Quality Baseline
→ ML Inference
→ Diagnosis
→ Dashboard

---

## 2. Main Components

### 2.1 VoIP Analysis Engine

Technology:

* Go

Responsibilities:

* Load PCAP files
* Identify relevant packets
* Parse SIP
* Parse SDP
* Identify RTP streams
* Parse RTCP when available
* Reconstruct calls
* Associate media streams with calls
* Calculate network/media features
* Produce a normalized feature representation

The analysis engine is the primary networking component of the application.

### 2.1.1 Dataset Export

The export layer converts the completed analysis result into a versioned research dataset.
Each exported row represents one analyzed RTP media stream. The exporter consumes the existing
feature, quality, E-model, diagnosis, and SDP metadata rather than recalculating metrics.

Supported formats:

* CSV for tabular ML workflows
* JSON for structured inspection and future API integration

Export flow:

PCAP
→ Analysis
→ Call Reconstruction
→ RTP/RTCP Metrics
→ Feature Extraction
→ Quality / E-model / Diagnosis
→ Dataset Export

Schema version: `1.0`. Unavailable measurements are represented explicitly: JSON uses `null`
for optional unavailable values, while CSV leaves those fields empty.

---


### 2.1.2 Shared Analysis Pipeline

The application uses a shared Go analysis service for HTTP consumers. The service centralizes the
pipeline that was previously orchestrated by the CLI:

```text
PCAP
→ SIP / SDP
→ RTP / RTCP
→ Call Reconstruction
→ Unified Media Metrics
→ Feature Extraction
→ Quality / E-model / Diagnosis
→ Native ML
```

The service returns normalized call/stream records and ML predictions without exposing the uploaded
file's temporary filesystem path to API clients.

---

### 2.2 Feature Extraction Layer

The feature extraction layer converts packet-level information into structured numerical and categorical features.

Initial features may include:

* packet_loss
* jitter_ms
* rtt_ms
* burst_loss_percent
* out_of_order_percent
* packet_rate
* duration_seconds
* packets_sent
* packets_received
* codec
* media_direction

Feature availability must be explicit.

Missing data must not be silently replaced with invented values.

---

### 2.3 Quality Baseline

The system contains a non-ML quality assessment baseline.

Responsibilities:

* Evaluate measurable network/media conditions
* Produce an engineering quality estimate
* Provide a baseline for ML experiments
* Provide explainable rule-based evidence

Where appropriate, an ITU-T E-model-based calculation can be used as a reference baseline.

The baseline must clearly document assumptions and limitations.

---

## 3. ML Architecture

Machine learning is implemented separately from the Go analysis engine.

Technology:

* Python
* NumPy
* pandas
* scikit-learn
* Optional XGBoost
* Optional SHAP

The ML system has two environments:

### Research Environment

Google Colab is used for:

* Dataset generation
* Data exploration
* Training
* Evaluation
* Model comparison
* Explainability experiments

### Runtime Environment

The final application uses an exported trained model locally.

The runtime application must not depend on Google Colab.

The runtime application must not require:

* Paid AI APIs
* Cloud AI services
* GPU
* Internet access

---

## 4. Model Lifecycle

The model lifecycle is:

Feature Design
→ Dataset Generation
→ Dataset Validation
→ Training
→ Evaluation
→ Model Selection
→ Export
→ Versioning
→ Local Inference

The exported artifact must include or reference:

* Model
* Preprocessing pipeline
* Feature schema
* Model version
* Training metadata

---

## 5. Go ↔ Model Integration

The research environment uses Python and scikit-learn for training and evaluation. The
runtime application is intentionally independent of Python.

Research flow:

```text
Go Feature Export
→ CSV / JSON
→ Google Colab
→ Model Training / Evaluation
→ Portable Random Forest Export
→ Model Verification
```

Runtime flow:

```text
PCAP
→ Analysis
→ Call Reconstruction
→ RTP/RTCP Metrics
→ Feature Extraction
→ Native Go Preprocessing
→ Embedded Random Forest
→ ML Prediction
```

The model artifact is a versioned JSON representation of the trained Random Forest. It contains
the ordered transformed feature schema, numeric medians, tree structures, leaf probabilities,
and class order.

The production runtime therefore does not require:

* Python
* scikit-learn
* Google Colab
* Internet access
* GPU
* paid AI APIs

The standalone `predict` command remains available, while `analyze` integrates the ML prediction
with the existing engineering score, E-model, and diagnosis output.

## 6. Diagnosis Layer

The diagnosis engine combines three evidence sources:

1. Measured network features
2. Engineering baseline/rules
3. ML prediction

Conceptually:

Measured Evidence
+
Engineering Rules
+
ML Prediction
→
Diagnosis

The diagnosis system must distinguish between:

* Observed fact
* Calculated metric
* Model prediction
* Probable cause
* Confidence/uncertainty

Example:

```text
Observed:
Packet loss = 4.8%

Observed:
Jitter = 42 ms

Model:
Quality = POOR

Diagnosis candidate:
Network degradation

Confidence:
0.89
```

The system must not present probabilistic model output as guaranteed physical root cause.

---

## 7. Simulator

The project includes a controlled synthetic VoIP/network simulator.

The simulator can generate reproducible scenarios involving:

* Packet loss
* Jitter
* Delay
* Burst loss
* Packet reordering
* Packet rate changes
* Codec variations

Example:

```text
Loss: 5%
Jitter: 40 ms
RTT: 150 ms
Burst loss: 2%
Reordering: 1%
```

The simulator may produce either:

* synthetic feature records
* synthetic RTP-like traces
* synthetic research datasets

The simulator is used for:

* Demonstrations
* Testing
* Dataset generation
* Research experiments

---

## 8. Dashboard Architecture

The web interface receives analysis results from the application API.

Conceptual flow:

PCAP
→ Go Engine
→ Analysis Result
→ Diagnosis
→ API
→ Web UI


### 8.1 Local HTTP API

The local HTTP API is implemented with the Go standard library (`net/http`) and is exposed by a
separate `callquality-api` command.

Endpoints:

```text
GET  /api/v1/health
GET  /api/v1/version
POST /api/v1/analyze
```

`POST /api/v1/analyze` accepts a `multipart/form-data` upload using the field name `file` and
returns one structured JSON document containing capture statistics, call summaries, per-stream
RTP/RTCP measurements, engineering quality, E-model values, rule-based diagnosis, and native ML
prediction.

The default server binds to `127.0.0.1:8080` and limits uploaded PCAP files to 64 MiB. The API
uses temporary files for request-scoped captures and removes them after analysis.

No third-party web framework is required.

The dashboard should display:

* Call summary
* Quality score
* Quality class
* Packet loss
* Jitter
* RTT
* Call timeline
* Quality degradation events
* Diagnosis
* ML confidence
* Feature importance/explanation

---

## 9. Research Architecture

Research files live under:

```text
research/
```

Expected structure:

```text
research/
├── notebooks/
├── datasets/
├── experiments/
├── results/
└── README.md
```

Google Colab notebooks are stored/exported here or linked from here.

The research workflow is:

```text
Generate Dataset
↓
Explore Dataset
↓
Validate Dataset
↓
Create Baseline
↓
Train Models
↓
Evaluate Models
↓
Explain Predictions
↓
Save Results
```

---

## 10. Repository Architecture

Target repository:

```text
callquality-ai/
│
├── app/
│   ├── cmd/
│   ├── internal/
│   ├── api/
│   └── ...
│
├── ml/
│   ├── inference/
│   ├── model/
│   ├── schema/
│   └── ...
│
├── research/
│   ├── notebooks/
│   ├── datasets/
│   ├── experiments/
│   ├── results/
│   └── README.md
│
├── docs/
│   ├── ARCHITECTURE.md
│   └── ...
│
└── PROJECT_SPEC.md
```

---

## 11. Runtime Principle

The final application must be usable locally.

Desired runtime flow:

```text
User
 ↓
CallQuality AI
 ↓
PCAP Analysis
 ↓
Feature Extraction
 ↓
Quality Baseline
 ↓
ML Inference
 ↓
Diagnosis
 ↓
Dashboard / CLI
```

Google Colab is not part of the runtime dependency chain.

---

## 12. Reproducibility

Experiments must use:

* Versioned datasets
* Fixed random seeds where appropriate
* Versioned models
* Documented feature schema
* Documented preprocessing
* Documented training configuration

A research result must be reproducible from the documented experiment configuration.

---

## 13. Dependency Principles

Before selecting or installing any third-party dependency:

1. Verify compatibility with the selected Go, Python, Node.js, React, and frontend versions.
2. Prefer stable and actively maintained libraries.
3. Avoid unnecessary dependencies.
4. Prefer standard-library functionality when practical.
5. Document important dependency decisions.

---

## 14. Architectural Goals

The architecture should prioritize:

* Separation of concerns
* Local-first execution
* Reproducibility
* Testability
* Replaceable ML inference
* Protocol correctness
* Clear evidence flow
* Minimal runtime dependencies
* Research/application separation

The application and research pipeline must remain independently testable.
