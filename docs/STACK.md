# CallQuality AI — Technology Stack

## Runtime Versions

### Backend / Network Engine

* Go 1.27.1
* Windows amd64 development environment

### Machine Learning / Research

* Python 3.12.7
* Google Colab for reproducible experiments

### Frontend

* Node.js 24.19.0 LTS
* npm 11.17.0
* React 19.3.0
* Vite 8.3.x
* TypeScript

### Version Control

* Git 2.55.0

---

## Core Architecture

### Go

Go is the primary application and networking language.

Responsibilities:

* PCAP/PCAPNG reading
* Packet processing
* Protocol identification
* SIP parsing
* SDP parsing
* RTP parsing
* RTCP parsing
* Call reconstruction
* Feature extraction
* Quality baseline
* Diagnosis engine
* CLI
* API
* Application orchestration

---

## Network Packet Processing

Primary dependency:

* github.com/gopacket/gopacket

The project will use gopacket primarily for packet decoding and PCAP/PCAPNG handling.

The project should prefer gopacket/pcapgo for offline packet-file processing.

The application must not require libpcap/Npcap for offline PCAP analysis unless a future live-capture feature explicitly requires it.

---

## Protocol Parsing Strategy

The following protocol parsers should be implemented as project-owned components wherever practical:

* SIP
* SDP
* RTP
* RTCP

Reason:

* reduce unnecessary dependencies
* maintain protocol-level control
* make packet-analysis logic explicit
* improve educational and research value
* allow custom validation and feature extraction

Generic packet decoding can use gopacket.

---

## Machine Learning Stack

Python responsibilities:

* Dataset generation
* Dataset validation
* Feature preprocessing
* Model training
* Model evaluation
* Explainability
* Research experiments
* Model export

Initial libraries:

* NumPy
* pandas
* scikit-learn
* joblib

Potential later libraries:

* XGBoost
* SHAP

Additional ML dependencies must only be introduced when an experiment demonstrates that they are justified.

---

## ML Model Strategy

The project will initially investigate lightweight CPU-friendly models.

Candidate models:

* Logistic Regression
* Random Forest
* Gradient Boosting
* XGBoost

The final model must be selected based on measured experimental results.

The project does not require:

* LLM APIs
* OpenAI API
* Gemini API
* Claude API
* cloud inference
* GPU training
* large local language models

---

## Model Artifact

The trained model will be exported as a versioned artifact.

The model artifact must be accompanied by:

* preprocessing pipeline
* feature schema
* model version
* training metadata
* compatible library/runtime information

The runtime application must use the trained artifact locally.

---

## Go ↔ ML Integration

The initial integration should use a clearly versioned local interface between the Go application and the ML inference component.

Conceptual flow:

Go Application
→ Feature Object
→ ML Inference
→ Prediction
→ Go Application

Communication should use a stable JSON schema.

Example request:

```json
{
  "model_version": "v1",
  "features": {
    "packet_loss": 3.7,
    "jitter_ms": 31.2,
    "rtt_ms": 146.0,
    "burst_loss_percent": 1.8,
    "out_of_order_percent": 0.4,
    "packet_rate": 50.0
  }
}
```

Example response:

```json
{
  "model_version": "v1",
  "quality_class": "DEGRADED",
  "confidence": 0.87,
  "score": 71.0
}
```

The transport mechanism may initially be a local process or localhost service.

The inference interface must remain replaceable.

---

## Frontend

Frontend technology:

* React
* TypeScript
* Vite

Responsibilities:

* analysis dashboard
* call details
* quality timeline
* feature visualization
* diagnosis display
* model explanation
* simulator interface
* research/demo views

The frontend should remain independent of the ML training environment.

---

## Storage

Initial storage:

* SQLite

Storage should be used only where persistent application state is actually required.

The first MVP should avoid unnecessary database complexity.

---

## Research Environment

Google Colab is a research environment rather than a runtime dependency.

Research responsibilities:

* dataset generation
* exploratory analysis
* training
* model comparison
* evaluation
* visualization
* explainability
* experiment tracking

Research notebooks must be exportable and reproducible.

---

## Research Artifacts

Research artifacts should be organized under:

```text
research/
├── notebooks/
├── datasets/
├── experiments/
└── results/
```

Large datasets should not automatically be committed directly into the Git repository.

Small sample datasets may be committed for reproducibility and demonstrations.

---

## Dependency Policy

Before adding any third-party dependency:

1. Verify compatibility with the selected runtime versions.
2. Verify that the dependency is actively maintained.
3. Prefer stable releases.
4. Prefer standard-library functionality when sufficient.
5. Avoid duplicating functionality already provided by existing dependencies.
6. Document important dependency decisions.
7. Do not add a dependency only for convenience when a small project-owned implementation is reasonable.

---

## Local-First Requirement

The application must remain usable without:

* Google Colab
* paid APIs
* cloud AI services
* internet connectivity at runtime
* GPU hardware

The internet may be required during development to download dependencies or optional external datasets.

---

## Reproducibility

Research experiments must record:

* Python version
* library versions
* random seed
* dataset version
* feature schema version
* model version
* training parameters

The objective is to allow another developer to reproduce reported experiments.

---

## Engineering Principle

The application is the product.

Google Colab is the laboratory.

The trained model is the bridge between the two.

The final architecture must preserve this separation.
