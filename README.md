# CallQuality AI

Local-first VoIP call quality analysis and prediction platform built around SIP/SDP, RTP/RTCP, engineering-based quality assessment, explainable machine learning, and reproducible synthetic experiments.

CallQuality AI transforms packet-level VoIP evidence from PCAP captures into an interpretable quality report, combining protocol analysis, measurable network metrics, an engineering quality baseline, diagnosis rules, and a lightweight native ML inference layer.

> Built as both an engineering tool and a reproducible research project.

---

## Overview

VoIP quality problems are often easy to observe but difficult to explain.

Symptoms such as packet loss, jitter, latency, reordering, unstable media, or one-way audio can originate from different layers of the communication path. Investigating them typically requires combining signaling information, media streams, RTP/RTCP statistics, and network-level observations.

CallQuality AI is designed to reduce that analysis effort by turning low-level VoIP evidence into structured, understandable quality information.

### Analysis Pipeline

```text
PCAP
  │
  ├── SIP / SDP
  │
  ├── RTP
  │
  └── RTCP
        │
        ▼
Protocol & Media Analysis
        │
        ▼
Feature Extraction
        │
        ├── Engineering Quality Assessment
        │
        ├── E-model / MOS Estimate
        │
        ├── Diagnosis Engine
        │
        └── Native ML Inference
                │
                ▼
        Unified Call Quality Report
                │
                ▼
        CLI / REST API / Web Dashboard
```

## Key Features

### PCAP-Based VoIP Analysis

Analyze classic `.pcap` captures locally without requiring a live production VoIP environment.

The analyzer can work with:

- SIP
- SDP
- RTP
- RTCP
- IP
- UDP
- TCP where relevant to signaling

### RTP Analysis

Extract measurable RTP stream characteristics including:

- Packet count
- Unique packets
- Duplicate packets
- Lost packets
- Packet-loss percentage
- Sequence gaps
- Out-of-order packets
- Inter-arrival jitter
- Packet-rate statistics
- Media direction

### RTCP Analysis

When RTCP evidence is available, the analyzer can extract and correlate:

- Receiver Reports
- Sender Reports
- Reported packet loss
- Reported jitter
- Passive RTT estimates
- RTP / RTCP stream relationships

### Engineering-Based Quality Assessment

The project includes a non-ML quality baseline based on measurable network/media conditions.

Quality factors include:

- Packet loss
- Jitter
- RTT
- Packet reordering
- Duplicate packets

The quality engine produces an explainable score and quality level rather than treating ML as the only source of truth.

### E-Model Baseline

Where the required evidence is available, CallQuality AI also calculates a simplified E-model-based quality estimate for a narrowband G.711-oriented baseline.

The resulting MOS value is an **estimated engineering metric**, not a substitute for subjective human listening tests.

### Diagnosis Engine

The diagnosis layer combines measured evidence and engineering rules to surface probable degradation factors such as:

- High packet loss
- High jitter
- High RTT
- Packet reordering
- Duplicate packets
- Mixed degradation
- Insufficient evidence
- RTP / RTCP metric disagreement
- Unavailable measurements

The system distinguishes evidence from inference and does not treat a detected condition as an absolute physical root cause.

### Native Machine Learning

CallQuality AI includes a lightweight CPU-friendly ML prediction layer.

The research pipeline evaluates classical tabular models such as:

- Logistic Regression
- Random Forest
- Gradient Boosting

The selected model is exported as a versioned artifact and embedded into the Go application for local inference.

The runtime application does not require:

- Google Colab
- A cloud AI service
- A paid API
- A GPU
- An always-on external service

The model and feature schema are versioned together so that research-time preprocessing can be reproduced consistently in the application.

---

## Machine Learning

The ML layer is designed as an experimental prediction component rather than a replacement for engineering analysis.

### Research Objective

The central research question is:

> Can lightweight machine-learning models use RTP/RTCP-derived network features to predict VoIP call-quality degradation and identify dominant contributing factors?

The research pipeline focuses on:

- Quality classification
- Feature analysis
- Model comparison
- Explainability
- Reproducible experiments
- Benchmarking

### Feature-Driven Prediction

The model works with structured network/media features extracted by the Go analyzer rather than raw audio.

This keeps the project:

- Lightweight
- Local-first
- CPU-friendly
- Reproducible
- Independent of paid AI services

The project does not depend on LLMs or generative AI for its core analysis.

---

## Reproducible Synthetic Dataset

Because the project is designed without requiring a physical VoIP laboratory, it includes controlled synthetic traffic generation for research and testing.

Synthetic scenarios can vary factors such as:

- Packet loss
- Jitter
- RTT
- Burst loss
- Packet reordering
- Packet rate
- Codec
- Call duration

The synthetic pipeline is intended for controlled experimentation, reproducible testing, demonstrations, and dataset generation.

It is explicitly separated from real-world VoIP validation and is not presented as equivalent to production traffic.

### Included Sample Captures

The repository contains a small set of demonstration PCAPs representing different impairment conditions:

```text
samples/
├── demo/
│   ├── synthetic-clean-v2.pcap
│   ├── loss-003.pcap
│   ├── jitter-003.pcap
│   ├── latency-003.pcap
│   ├── reorder-003.pcap
│   ├── duplicate-003.pcap
│   └── combined-003.pcap
│
└── synthetic-dataset-v4/
    ├── dataset.csv
    └── manifest.csv
```

The larger synthetic dataset is retained for reproducible ML experiments, while the `demo` directory provides representative captures for quick evaluation.

---

## CLI

The primary application is written in Go.

### Analyze a PCAP

```bash
callquality analyze call.pcap
```

### Export Structured Features

```bash
callquality export call.pcap --format csv --output features.csv
```

```bash
callquality export call.pcap --format json --output features.json
```

### Run ML Prediction

```bash
callquality predict call.pcap
```

### Show Version

```bash
callquality version
```

The Go analyzer remains the source of truth for feature calculation and dataset export. The export schema is versioned to support reproducible research workflows.

---

## Local HTTP API

A local REST API is provided for the web dashboard and other local clients.

### Endpoints

```text
GET  /api/v1/health
GET  /api/v1/version
POST /api/v1/analyze
```

### Start the API

From the `app` directory:

```bash
go run ./cmd/callquality-api
```

The default API address is:

```text
http://127.0.0.1:8080
```

For the included web dashboard development setup, the API can be started on port `8090`:

```bash
go run ./cmd/callquality-api -listen 127.0.0.1:8090
```

The default maximum PCAP upload size is `64 MiB`.

---

## Web Dashboard

CallQuality AI includes a React + TypeScript dashboard for interactive local analysis.

The dashboard is designed around technical clarity and presents:

- Capture summary
- Reconstructed calls
- Quality score and level
- RTP metrics
- RTCP metrics
- E-model / MOS estimate
- Diagnosis findings
- ML prediction
- Prediction probabilities
- Stream-level analysis
- API / dashboard status

### Run the Dashboard

From the `web` directory:

```bash
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

The Vite development server proxies `/api` requests to the local Go API.

For the current development setup:

```text
Web Dashboard
127.0.0.1:5173

        │
        ▼

Go API
127.0.0.1:8090
```

The web layer is a local visualization interface; the core analysis remains implemented in Go.

---

## Architecture

```text
CallQuality AI/
│
├── app/
│   ├── cmd/
│   │   ├── callquality/
│   │   ├── callquality-api/
│   │   ├── datasetgen/
│   │   └── gencapture/
│   │
│   └── internal/
│       ├── analyzer/
│       ├── api/
│       ├── callanalysis/
│       ├── diagnosis/
│       ├── emodel/
│       ├── export/
│       ├── features/
│       ├── ml/
│       ├── pcap/
│       ├── pipeline/
│       ├── quality/
│       ├── rtcp/
│       ├── rtp/
│       ├── sdp/
│       └── sip/
│
├── docs/
│   ├── API.md
│   ├── ARCHITECTURE.md
│   ├── DATASET.md
│   ├── ML_INFERENCE.md
│   └── STACK.md
│
├── research/
│   └── models/
│
├── samples/
│   ├── demo/
│   └── synthetic-dataset-v4/
│
├── web/
│   ├── src/
│   └── ...
│
├── PROJECT_SPEC.md
└── README.md
```

---

## Technology Stack

### Core

- Go
- gopacket
- Standard Go networking and HTTP packages

### VoIP / Network Analysis

- SIP
- SDP
- RTP
- RTCP
- PCAP

### Machine Learning

- Python
- NumPy
- pandas
- scikit-learn
- Exported Random Forest model for native inference

### Frontend

- React
- TypeScript
- Vite

### Research Environment

- Google Colab for experimentation and model training

Google Colab is used as a research environment rather than as a runtime dependency of the final application.

---

## Design Principles

The project is built around several engineering principles:

- Correctness over unsupported assumptions
- Reproducibility
- Explainability
- Local-first execution
- Measurable results
- Clear separation between evidence and inference
- Minimal unnecessary dependencies
- Strong automated testing
- Clear technical documentation

These principles are central to both the application and the research workflow.

---

## Testing

The project includes automated tests across the major Go components, including:

- PCAP reading and decoding
- SIP parsing
- SDP parsing
- RTP parsing
- RTP stream tracking
- RTP jitter calculation
- RTCP parsing
- RTP / RTCP correlation
- Media metrics
- Feature extraction
- Quality assessment
- E-model calculations
- Diagnosis rules
- Call analysis
- API behavior
- Dataset generation
- ML inference

The project is intended to keep protocol analysis and quality calculations independently testable while maintaining an integrated end-to-end pipeline.

---

## Limitations

CallQuality AI is an engineering and research project, not a production carrier-grade voice-quality measurement system.

Important limitations include:

- Synthetic datasets do not represent the full variability of real-world VoIP traffic.
- Network metrics do not perfectly capture subjective human perception.
- E-model / MOS outputs are estimates based on available network/media evidence.
- The current system does not replace subjective listening tests.
- ML predictions depend on the data and experimental conditions used during training.
- Real-world generalization requires validation against larger and more diverse production captures.
- Some metrics may be unavailable when the required protocol evidence is not present.

The project intentionally avoids unsupported claims about model or quality-estimation performance.

---

## Non-Goals

The MVP does not require:

- Live SIP server integration
- Live RTP packet capture
- Asterisk deployment
- Physical IP phones
- Cloud infrastructure
- Large language models
- Paid AI APIs
- GPU training
- Speech recognition
- Automatic call recording
- Production carrier integration

These can be considered future extensions rather than requirements for the current architecture.

---

## Documentation

Detailed technical documentation is available in:

- [`docs/API.md`](docs/API.md) — Local HTTP API
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — System architecture
- [`docs/DATASET.md`](docs/DATASET.md) — Dataset and synthetic-data workflow
- [`docs/ML_INFERENCE.md`](docs/ML_INFERENCE.md) — Native ML inference
- [`docs/STACK.md`](docs/STACK.md) — Technology stack
- [`PROJECT_SPEC.md`](PROJECT_SPEC.md) — Project specification and research direction

---

## Project Goal

CallQuality AI is designed to demonstrate a complete engineering and research pipeline:

```text
Network Evidence
      ↓
Protocol Analysis
      ↓
Feature Extraction
      ↓
Engineering Baseline
      ↓
Machine Learning
      ↓
Explainability
      ↓
Diagnosis
      ↓
Visualization
      ↓
Benchmarking
      ↓
Reproducible Research
```

The project is intended to function as both:

1. A practical local VoIP analysis tool
2. A reproducible experimental research project

---

## License

License information will be added with the repository release.