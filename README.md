# O-RAN xApps, Experiment Orchestration & ML-based Malicious UE Detection

> End-to-end framework for generating realistic multi-UE 4G/5G RAN experiments (benign + attack traffic), collecting standardized O-RAN KPM Style 5 metrics, engineering temporal features, and performing cascaded multi-stage malicious UE classification inside a Near-RT RIC python xApp.

---
## 1. High-Level Overview
This repository contains:
- **O-RAN Near-RT RIC xApps** for:
  - Collecting E2SM-KPM Report Service *Style 5* metrics (`kpm5_xapp.py`).
  - Performing *in-memory feature engineering* + *cascaded ML inference* to detect and classify malicious UE behavior (`detector_xapp.py`).
- **Experiment generation tooling** (`generate_experiments.py`, `generate_malicious_experiments.py`) producing structured per-run folders with traffic profiles & radio channel parameters.
- **Full automation script** (`run_enhanced.sh`) that orchestrates: RIC stack, core (Open5GS), srsRAN gNB + UEs, GNU Radio fading/channel scenario, traffic generation (iperf profiles), metric capture, retries, health checks, and cleanup.
- **Custom temporal feature pipeline** embedded directly in the detector xApp (rolling aggregations, derived ratios, jitter & imbalance metrics, flags, etc.).
- **ML model integration** (Stage 1 binary + Stage 2 multi-class benign/malicious subtype refinement) using joblib-loaded PyTorch / sklearn-compatible models.

The system enables *repeatable dataset creation* and *online inference* without writing intermediate CSVs for the detector (buffer-based streaming processing).

---
## 2. Architecture
```
+----------------------+        +---------------------+       +------------------+
|  Traffic Profiles &  |        |  Experiment Folders |       |  run_enhanced.sh |
|  (iperf scripts)     |  --->  |  trX/expY:           |  -->  |  Orchestrator    |
|  normal/malicious    |        |   - conditions.csv   |       |  (RIC+Core+RAN)  |
+----------+-----------+        |   - run_scenario.sh  |       +---------+--------+
           |                     |   - metrics/         |                 |
           |                     +----------+-----------+                 |
           v                                |                             v
   generate_experiments.py /                |                   Near-RT RIC (docker)
   generate_malicious_experiments.py        |                   - submgr / e2term / appmgr
                                            v                   - python_xapp_runner
                                  GNU Radio Channel Model               |
                                            |                           |
                                     srsRAN gNB (tmux) <---- E2 ----> KPM xApp
                                            |                                 \
                                      UE netns (srsUE x N)                     \
                                            |                                   \
                                   iperf traffic (benign/malicious)             \
                                            |                                    \
                                            +--------> Detector xApp (buffer -> engineered features -> cascade models)
``` 

Key flows:
- E2SM-KPM Style 5 subscription delivers per-UE metrics → CSV (collector xApp) or in-memory buffer (detector).
- Detector xApp transforms raw metrics into temporal + structural features → cascaded model → per-UE decision.
- Experiment orchestration ensures reproducibility and resilience with retries & health checks.

---
## 3. Core Components
| Component | File(s) | Purpose |
|-----------|---------|---------|
| KPM Metrics Collector xApp | `kpm5_xapp.py` | Subscribes to Style 5, writes wide CSV (one row per UE per indication) |
| Malicious Detector xApp | `detector_xapp.py` | Buffers metrics, engineers features, cascaded prediction (Stage 1 binary → Stage 2 subtype) |
| xApp Base Abstraction | `openran/oran-sc-ric/xApps/python/lib/xAppBase.py` | Wraps RMR init, HTTP subscription callbacks, threading, subscription dispatch |
| E2SM-KPM Handling | `openran/oran-sc-ric/xApps/python/lib/e2sm_kpm_module.py` (not expanded here) | Packs/unpacks KPM indications and subscription payloads |
| Experiment Generator (benign) | `generate_experiments.py` | Creates structured experiment folders with M-map stochastic assignment |
| Experiment Generator (malicious) | `generate_malicious_experiments.py` | Same as above but injects malicious traffic profiles (2 malicious UEs / run) |
| Orchestrator Script | `run_enhanced.sh` | Starts/stops entire stack, health checks, retries, validates outputs |
| Models | `openran/oran-sc-ric/xApps/python/lib/ml_models.py` & external `.joblib` artifacts | Defines neural architectures used during training/inference |
| GNU Radio Scenario | `multi_ue_scenario.grc` / generated runner scripts | Provides RF/channel impairment dynamics |

---
## 4. Experiment Folder Layout
Each generated experiment (e.g. `generated_malicious_experiments/tr12/exp1/`) contains:
```
conditions.csv        # UE ↔ iperf profile mapping + M-map & channel params
run_scenario.sh       # Launches GNU Radio scenario & writes PID to /tmp/python_scenario.pid
metrics/              # Output metrics (if collector xApp used)
ue_logs/              # Per UE stdout, metrics CSV, pcap, tracing
gnb_logs/             # gNB logs, pcap traces
```
The orchestrator later augments these directories with runtime artifacts.

---
## 5. KPM Metrics & Feature Engineering
Raw subscribed metrics (default list):
```
RRU.PrbAvailDl, RRU.PrbAvailUl, RRU.PrbUsedDl, RRU.PrbUsedUl,
RACH.PreambleDedCell, DRB.UEThpDl, DRB.UEThpUl,
DRB.RlcPacketDropRateDl, DRB.RlcSduTransmittedVolumeDL, DRB.RlcSduTransmittedVolumeUL,
CQI, RSRP, RSRQ, DRB.RlcSduDelayDl, DRB.RlcDelayUl
```
Derived (detector) features include (non-exhaustive):
- PRB utilization & efficiency ratios (DL/UL)
- Throughput/volume normalization
- Resource & delay imbalance metrics
- Signal composite index (CQI+RSRP+RSRQ)/3
- Jitter (rolling diff) of RLC delays
- Zero-activity & poor-signal flags
- Rolling window (size=5) mean/std for selected base + derived signals
- Epoch timestamp alignment

The detector reindexes engineered frame to the feature signature expected by loaded models (`self.selected_features`).

---
## 6. Cascaded Malicious UE Detection
1. **Stage 1 (Binary)**: Malicious vs Benign (majority vote aggregated per UE across buffered rows).
2. **Stage 2 (Subtype)**: Two specialist models:
   - Benign subtype classifier (embb, mtc, urllc, voip)
   - Malicious subtype classifier (udp_flood, fragmentation, pulsing variants, small packet, parallel floods, etc.)
3. **Cascade Output**: Per row and aggregated per UE (e.g., `UE 2 → Malicious-udp_flood`).
4. **Buffer Driven**: Processing triggered when buffer reaches configured size (`--buffer_size`, default 30) and periodically cleared after large accumulation (1440 rows safeguard).

---
## 7. Orchestration Workflow (`run_enhanced.sh`)
Major phases (with retries/backoff):
1. Start Near-RT RIC (Docker Compose) → wait for `ric_submgr` health.
2. Start Open5GS core → wait for health (container healthcheck).
3. Start gNB (srsRAN) with metrics & extensive pcap logging.
4. Create UE network namespaces & start 3 srsUE instances (per-UE config from `ue_data.csv`).
5. Launch GNU Radio fading/channel scenario via per-experiment `run_scenario.sh`.
6. Start traffic (iperf) per UE according to profiles in `conditions.csv`.
7. (Optionally) run KPM collector/detector xApps via `python_xapp_runner` container.
8. Validate metrics duration, cleanup (tmux sessions, namespaces, Docker, ports, temp files).

Resilience features:
- Port freeing + process killing for stale runs.
- Health & connection polling (E2 + N2 + UE RRC + PDU).
- Structured retry wrapper (`retry_with_backoff`).
- Experiment state file for traceability.
- Duration validation of metrics CSV.

---
## 8. Running the Stack
### 8.1 Prerequisites
- Linux host with Docker & Docker Compose
- srsRAN (included) and Open5GS dependencies (handled via containers for core)
- Python 3.8+ for xApps & tooling
- iperf3 available inside core container (auto-started servers)
- Traffic profile shell scripts under `traffic_profiles/`

### 8.2 Start RIC + Run Collector xApp Manually
```bash
cd openran/oran-sc-ric
docker compose up -d
# Enter runner and launch xApp
docker compose exec python_xapp_runner bash -c "./kpm5_xapp.py --metrics_dir metrics --ue_ids 0,1,2"
```

### 8.3 Run Detector xApp
Place model artifacts in the mounted `xApps/python` directory (or provide relative paths). Then:
```bash
docker compose exec python_xapp_runner bash -c "./detector_xapp.py \
  --s1_model_path s1_model.joblib \
  --s2_ben_path s2_benign_model.joblib \
  --s2_mal_path s2_malicious_model.joblib \
  --buffer_size 60 --ue_ids 0,1,2"
```

### 8.4 Generate Experiments
```bash
python3 generate_experiments.py            # benign runs (50 by default)
python3 generate_malicious_experiments.py  # malicious-injected runs (100 by default)
```

### 8.5 Full Automated Run (Malicious Set Example)
Edit path constants near the top of `run_enhanced.sh` (or parameterize) then:
```bash
bash run_enhanced.sh 0 1   # start from training set 0, experiment 1
```

---
## 9. Data & Metrics Output
- Collector CSV: `metrics/kpm_style5_metrics.csv` wide form (Timestamp, E2AgentID, SubscriptionID, UE_ID, Granularity, <metrics...>).
- Detector: In-memory only (unless extended) – could be extended to emit prediction logs.
- UE logs: `ue_logs/ueX_metrics.csv` (native srsUE metrics if enabled) + pcaps.
- gNB logs & pcaps: deep protocol tracing for post-hoc analysis.

---
## 10. Models & Extensibility
Model artifacts (`*.joblib`) expected to deserialize into either:
- PyTorch `nn.Module` objects, or
- sklearn-like estimators exposing `.predict()`.

To add a new feature:
1. Add computation inside `_feature_engineer_network_data`.
2. Include it in rolling window list if aggregated temporal stats needed.
3. Retrain models ensuring `self.selected_features` ordering updated.

To support output logging of predictions, extend `predict_cascaded()` to append to a CSV or push RMR control messages.

---
## 11. Safety & Cleanup Considerations
- Script force-kills processes on key ports (2000–2301, 55555). Avoid unrelated services on those ports.
- Network namespaces (`ue1..ue3`) are deleted at cleanup.
- Route `10.45.0.0/16 via 10.53.1.2` added if missing; removed on teardown.
- Ensure sufficient system limits for many pcap/log files (disk IO & storage).

---
## 12. Known Limitations / Future Work
| Area | Improvement |
|------|-------------|
| Config Hardcoding | Externalize paths (CSV_FILE, BASE_EXP_DIR) via env/CLI args. |
| Model Feature Sync | Automate persistence of `selected_features` to avoid mismatch risk. |
| Detector Persistence | Log per-UE classification timeline to disk for auditing. |
| Real-time Control | Add RIC control messages when malicious UE detected (e.g., throttle or isolate). |
| CI Testing | Add unit tests mocking E2 indications & feature pipeline correctness. |
| Metrics Streaming | Optionally stream engineered features to a time-series DB (e.g., InfluxDB, Prometheus). |
| Parameter Search | Integrate automated hyperparameter search & model registry. |
| Visualization | Dashboard for live UE status & feature trends. |

---
## 13. Quick Reference (Commands)
| Action | Command (example) |
|--------|-------------------|
| Start RIC | `cd openran/oran-sc-ric && docker compose up -d` |
| Run KPM xApp | `docker compose exec python_xapp_runner ./kpm5_xapp.py --ue_ids 0,1,2` |
| Run Detector xApp | `docker compose exec python_xapp_runner ./detector_xapp.py --buffer_size 60` |
| Generate Benign Experiments | `python3 generate_experiments.py` |
| Generate Malicious Experiments | `python3 generate_malicious_experiments.py` |
| Run Automated Pipeline | `bash run_enhanced.sh 0 1` |

---
## 14. Citation / Academic Context
This repository underpins a dissertation project exploring **online RAN telemetry analytics for malicious UE behavior detection** using **multi-stage classification** and **temporal feature extraction** over **E2SM-KPM Style 5 streams** within an **O-RAN Near-RT RIC** testbed.

If publishing, cite O-RAN specifications and srsRAN / Open5GS projects accordingly.

---
## 15. Glossary
- **E2SM-KPM**: E2 Service Model – Key Performance Measurements.
- **Style 5**: Report style delivering per-UE measurement data in tabular form.
- **PRB**: Physical Resource Block.
- **CQI/RSRP/RSRQ**: Standard radio quality indicators.
- **M-map Generator**: Stochastic sequence generator producing pseudo-random but controllable assignments.
- **Cascade Model**: Sequential inference pipeline (coarse→fine classification).

---
## 16. License & Attribution
See upstream component licenses (O-RAN SC images, srsRAN, Open5GS). Local additions fall under the repository's chosen license (add a `LICENSE` file if not already present for clarity).

---
## 17. Contact & Contributions
Open to extensions (pull requests) focusing on: configuration externalization, control-plane reactions, richer model evaluation, or visualization tooling.

---
### ✅ Status
Core functionality implemented: experiment generation, orchestration, KPM collection, feature engineering, cascaded detection. Ready for iterative refinement & evaluation.
