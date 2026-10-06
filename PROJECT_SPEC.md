# CallQuality AI

## 1. Project Overview

CallQuality AI is a local-first VoIP call quality analysis and prediction platform.

The system analyzes network-level VoIP data, primarily RTP/RTCP and related SIP/SDP information, extracts measurable communication-quality features, evaluates call quality using an engineering baseline, and optionally uses a lightweight machine-learning model to predict quality degradation and identify its dominant contributing factors.

The project is designed to work without:

* Paid AI APIs
* Cloud AI services
* GPU
* A physical VoIP laboratory
* Live production calls

The project must be reproducible on a normal developer machine.

---

## 2. Problem Statement

VoIP call problems are often observed as symptoms such as:

* Poor voice quality
* High jitter
* Packet loss
* High latency
* One-way audio
* Intermittent media degradation
* Unstable call quality

The difficult part is determining why the quality degraded.

Engineers often need to combine information from SIP signaling, SDP negotiation, RTP/RTCP statistics, packet-level observations, and network conditions.

CallQuality AI aims to reduce this analysis effort by transforming low-level VoIP network evidence into an understandable quality report and probable diagnosis.

---

## 3. Primary Users

The initial target users are:

* VoIP Engineers
* Network Engineers
* NOC Engineers
* System Administrators
* Telecom students and researchers
* Developers working with SIP/RTP systems

---

## 4. Core Inputs

The primary input for the first version is a PCAP file.

Supported protocol/data sources may include:

* SIP
* SDP
* RTP
* RTCP
* IP
* UDP
* TCP where relevant to signaling

The first MVP does not require live packet capture.

---

## 5. Core Analysis Features

The system should attempt to calculate or extract, when the required information exists:

* Call start time
* Call duration
* Codec
* Packets sent
* Packets received
* Packet loss
* Packet loss percentage
* RTP sequence gaps
* Out-of-order packets
* Inter-arrival jitter
* RTCP-reported jitter
* RTT where available
* RTP stream direction
* One-way media indicators
* Burst-loss indicators
* Packet-rate statistics

The system must clearly distinguish between:

* observed values
* calculated values
* unavailable values

The system must never invent a metric that cannot be reliably calculated from the available evidence.

---

## 6. Quality Assessment

The project will contain a non-ML quality assessment baseline.

The baseline should use documented engineering principles and, where appropriate, an established telecommunications quality model such as the ITU-T E-model.

The baseline must produce an estimated network/media quality result.

The project must clearly document the limitations of this estimate.

The system must not claim that a computed score is equivalent to a subjective human MOS test.

---

## 7. Machine Learning Objective

Machine learning will be used as an experimental prediction layer.

The primary ML objectives are:

1. Predict a call-quality class.
2. Estimate a quality-related score where the dataset supports it.
3. Identify the most influential input features.
4. Provide an interpretable explanation for the prediction.

Initial candidate quality classes:

* GOOD
* ACCEPTABLE
* DEGRADED
* POOR

The final label definition must be determined during the research phase rather than arbitrarily hard-coded without justification.

---

## 8. Candidate ML Models

The research phase should evaluate lightweight CPU-friendly models.

Initial candidates:

* Logistic Regression
* Random Forest
* Gradient Boosting
* XGBoost, if justified

Deep learning and large language models are not required for the initial project.

The final selected model must be based on experimental evidence rather than assumption.

---

## 9. Explainability

The ML system should provide interpretable information such as:

* Feature importance
* Model confidence/probability where supported
* SHAP-based explanations if appropriate
* Dominant quality-degradation factors

Example:

Predicted Quality: DEGRADED

Main contributing factors:

* Packet Loss
* Jitter
* RTT

The explanation must be presented as model evidence, not as an absolute physical root-cause claim.

---

## 10. Synthetic Dataset Strategy

Because the project does not depend on a physical VoIP laboratory, the research pipeline will include a controlled synthetic-data generation component.

The synthetic dataset may vary parameters such as:

* Packet loss
* Jitter
* RTT
* Burst loss
* Packet reordering
* Packet rate
* Codec
* Call duration

The dataset generator should support reproducible random seeds.

The research must clearly distinguish synthetic experiments from validation using real-world captures.

---

## 11. PCAP and Synthetic Data Relationship

The application and research pipeline should support two complementary paths:

### Real-world analysis

PCAP
→ Packet analysis
→ RTP/RTCP features
→ Quality analysis
→ Prediction

### Controlled research

Synthetic parameters
→ Synthetic RTP/network traces
→ Feature generation
→ Dataset
→ Training/evaluation

The synthetic pipeline must not pretend to be equivalent to real-world VoIP traffic.

---

## 12. Main Application Architecture

The application is intended to contain:

* Packet/PCAP analysis engine
* SIP/SDP analysis
* RTP analysis
* RTCP analysis
* Feature extraction
* Quality baseline
* ML inference
* Diagnosis engine
* REST API where useful
* Web dashboard
* CLI

---

## 13. Research Architecture

The research side should contain:

* Dataset generation
* Dataset validation
* Exploratory data analysis
* Feature analysis
* Baseline evaluation
* Model training
* Model comparison
* Explainability experiments
* Benchmarking
* Visualization
* Research conclusions

Google Colab is an experimentation environment, not a required runtime dependency of the final application.

---

## 14. Model Deployment Principle

The ML model must be trained during the research phase and exported as a versioned model artifact.

The final application must use the exported model locally.

The application must not require:

* Google Colab
* an external AI API
* an always-on cloud service

The model's preprocessing pipeline and feature schema must be versioned together with the model.

---

## 15. Diagnosis Engine

The final application should combine:

* measured network evidence
* engineering rules
* ML prediction
* explainability information

The diagnosis engine should produce probable causes such as:

* High packet loss
* High jitter
* High latency
* Burst loss
* One-way media
* RTP flow interruption
* Codec-related condition
* Insufficient evidence
* Mixed degradation

The system must explicitly communicate uncertainty.

---

## 16. Simulator

The application should eventually provide a controlled simulation mode.

Example:

Loss = 5%
Jitter = 40 ms
RTT = 150 ms
Burst loss = 2%

The simulator should be able to produce reproducible synthetic scenarios for:

* testing
* demonstrations
* dataset generation
* research experiments

---

## 17. Dashboard Goals

The dashboard should provide:

* Calls analyzed
* Quality distribution
* Call-level quality summary
* RTP/RTCP metrics
* Quality timeline
* Degradation events
* Prediction result
* Confidence/probability when available
* Feature importance/explanation
* Diagnosis summary

The UI should prioritize technical clarity over decorative complexity.

---

## 18. CLI Goals

The current CLI includes the analysis, dataset-export, and ML prediction paths:

```text
callquality analyze call.pcap

callquality export call.pcap --format csv --output features.csv

callquality export call.pcap --format json --output features.json

callquality predict call.pcap

callquality version
```

A local HTTP API is provided separately for the future web dashboard:

```text
GET  /api/v1/health
GET  /api/v1/version
POST /api/v1/analyze
```

Dataset export uses schema version `1.0` and emits one record per analyzed RTP media stream.
CSV is intended for direct tabular/ML workflows; JSON is intended for structured interchange
and inspection. The Go analyzer remains the source of truth for feature calculation.

Planned future commands may include:

callquality simulate

callquality generate-dataset

callquality benchmark

---

## 19. Research Question

Primary research question:

Can lightweight machine-learning models use RTP/RTCP-derived network features to predict VoIP call-quality degradation and identify the dominant contributing factors?

Potential secondary questions:

* Which network features contribute most strongly to quality prediction?
* How does ML performance compare with an engineering baseline?
* Can quality degradation be detected before severe degradation occurs?
* How robust are predictions across different synthetic impairment patterns?

---

## 20. Evaluation

The research should evaluate classification using appropriate metrics such as:

* Accuracy
* Precision
* Recall
* F1-score
* Confusion Matrix

For regression/score prediction where applicable:

* MAE
* RMSE
* R² where meaningful

Operational metrics may include:

* Inference latency
* Memory usage
* Dataset size
* Model size

All evaluation results must include the dataset and experimental conditions under which they were obtained.

---

## 21. Research Limitations

The project must explicitly document:

* Synthetic-data limitations
* Potential dataset bias
* Relationship between network metrics and perceived speech quality
* Limits of any estimated quality score
* Lack of large-scale real-world validation
* Model generalization limitations

The project must avoid unsupported claims.

---

## 22. Non-Goals for MVP

The MVP does not require:

* Live SIP server integration
* Live RTP capture
* Asterisk deployment
* Physical IP phones
* Cloud infrastructure
* Large language models
* Paid AI APIs
* GPU training
* Audio speech recognition
* Automatic call recording
* Production-grade carrier integration

These may be considered future extensions.

---

## 23. Initial Technology Direction

Core application:

* Go

Research/ML:

* Python
* NumPy
* pandas
* scikit-learn

Optional:

* XGBoost
* SHAP

Frontend:

* React
* TypeScript

Storage:

* SQLite initially

Research environment:

* Google Colab

All third-party dependencies must be evaluated for compatibility with the selected versions before adoption.

Prefer stable, actively maintained libraries and avoid unnecessary dependencies.

---

## 24. Design Principles

The project should prioritize:

* Correctness
* Reproducibility
* Explainability
* Local-first execution
* Engineering usefulness
* Measurable results
* Clear separation between evidence and inference
* Minimal unnecessary dependencies
* Strong automated testing
* High-quality documentation

---

## 25. Final Project Goal

CallQuality AI should ultimately demonstrate the complete engineering and research pipeline:

Network Evidence
→ Protocol Analysis
→ Feature Extraction
→ Engineering Baseline
→ Machine Learning
→ Explainability
→ Diagnosis
→ Visualization
→ Benchmark
→ Reproducible Research

The project should function both as:

1. A useful technical VoIP analysis tool.
2. A reproducible experimental research project suitable for a professional GitHub portfolio.
