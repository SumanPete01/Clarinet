# Clarinet — Transformer-Based Network Intrusion Detection System

Clarinet is a real-time intrusion detection pipeline that captures live network packets, converts them into flow-level statistical features, and classifies them with a custom Transformer model — all rendered on a live monitoring dashboard.

Unlike typical academic IDS demos that replay static CSV datasets through a model, Clarinet performs **live packet capture → flow reconstruction → feature extraction → transformer inference**, end to end, on real traffic.

---

## What This Project Does

1. Captures live traffic on a target ("victim") machine using `tshark`.
2. Converts captures into proper `.pcap` files and extracts **58 CICIDS-2017-style flow features** per network flow using **CICFlowMeter**.
3. Feeds those features into a **Transformer encoder** trained to classify each flow as **BENIGN** or one of five attack types.
4. Streams live predictions, traffic stats, and system health to a browser dashboard in real time over Server-Sent Events (SSE).
5. Includes an in-repo traffic generator to simulate attack load (e.g. HTTP flood) for demonstration and testing.

---

## Architecture

```
┌──────────────┐     tshark capture      ┌───────────────┐
│  Live Network │ ───────────────────────▶│  pcap_spool/  │
│   Traffic     │                         └───────┬───────┘
└──────────────┘                                  │ editcap (normalize)
                                                   ▼
                                           ┌───────────────┐
                                           │ pcap_inbox/   │
                                           └───────┬───────┘
                                                   │ CICFlowMeter
                                                   ▼
                                           ┌───────────────┐
                                           │ flow_outputs/ │ (*_Flow.csv)
                                           └───────┬───────┘
                                                   │ prepare_flows.py
                                                   ▼
                                       58-feature filtered CSV row
                                                   │
                                                   ▼
                                   ┌───────────────────────────────┐
                                   │   Tabular Transformer Model    │
                                   │  (PyTorch, trained offline)    │
                                   └───────────────┬────────────────┘
                                                   │ prediction + confidence
                                                   ▼
                                   ┌───────────────────────────────┐
                                   │  Flask server (SSE) + Dashboard│
                                   └───────────────────────────────┘
```

Processed and failed captures are moved into `pcap_done/` and `pcap_error/` respectively for traceability.

---

## Model

The classifier (`transformer/`) is a custom **Tabular Transformer** built from scratch in PyTorch:

- **Feature Tokenizer** — projects each of the 58 numeric flow features into a learned embedding space and adds a per-feature positional embedding, turning a flat feature vector into a sequence of tokens.
- **Transformer Encoder** — 2 encoder layers, 4 attention heads, `d_model=64`, applied over the tokenized features with a prepended `[CLS]` token (same pattern as ViT/BERT-style classification).
- **Classification Head** — LayerNorm → Linear → ReLU → Dropout → Linear, producing logits over 6 classes.

**Classes:** `BENIGN`, `DDoS`, `DoS GoldenEye`, `DoS Hulk`, `DoS slowloris`, `FTP-Patator`

Trained on an undersampled, class-balanced subset of CICIDS-2017-style flow data (`train.py`), using `StandardScaler`-normalized features, `AdamW`, and cross-entropy loss. The trained weights (`transformer_model.pth`) and fitted scaler (`scaler.pkl`) are loaded by the live server at startup and never retrained on live traffic.

---

## Live Dashboard

The `victim-dashboard/` Flask app is the "victim" machine's monitoring console:

- **Live traffic chart** — packets/sec and bandwidth in/out, updated every second.
- **ML detection panel** — current predicted class with confidence, plus a live probability breakdown across all 6 classes.
- **System health** — CPU and RAM usage of the monitored host.
- **Alert log** — a running, timestamped history of every non-benign prediction.
- **Attack-override logic** — if any attack class crosses a configurable confidence threshold, it's surfaced even when BENIGN still holds the raw top softmax score, favoring recall on suspicious flows.

The frontend is a single server-rendered page using vanilla JavaScript, Chart.js, and the native `EventSource` API for SSE — no frontend framework or build step.

---

## Repository Layout

```
Clarinet/
├── transformer/
│   ├── data/
│   │   ├── transformer_model.pth   # trained model weights
│   │   └── scaler.pkl              # fitted StandardScaler
│   ├── notebooks/
│   │   └── transformer_architecture.ipynb
│   └── scripts/
│       └── train.py                # model training + evaluation
│
├── victim-dashboard/
│   ├── server.py                   # Flask app: capture pipeline + inference + SSE
│   ├── prepare_flows.py            # maps raw CICFlow CSV → the 58 model features
│   ├── traffic_attack.py           # lab-only HTTP load generator for demos
│   ├── reset_pipeline.py           # clears spool/inbox/output folders
│   ├── templates/                  # dashboard frontend
│   └── README.md                   # detailed pipeline setup guide (per-machine config)
│
└── requirements.txt
```

---

## Running It

Full setup (tshark interface index, CICFlowMeter install/config for WSL or native Windows, environment variables, and troubleshooting) is documented in [`victim-dashboard/README.md`](./victim-dashboard/README.md). At a high level:

**Terminal 1 — start the server (pipeline + dashboard + inference):**
```powershell
cd victim-dashboard
python server.py
```

**Terminal 2 — capture live traffic into the spool:**
```powershell
tshark -i <interface_index> -f "tcp port 5000" -b duration:15 -b files:200 -w victim-dashboard\pcap_spool\cap.pcap
```

Then open `http://localhost:5000` to watch live classification. Optionally simulate attack traffic from another terminal:
```powershell
python victim-dashboard/traffic_attack.py --target http://<victim-ip>:5000 --workers 20 --duration 60
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Model | PyTorch (custom Transformer encoder) |
| Feature extraction | CICFlowMeter, `tshark` / `editcap` |
| Backend | Flask, Flask-CORS, Server-Sent Events |
| Data processing | pandas, NumPy, scikit-learn |
| Frontend | Vanilla JS, Chart.js, HTML/CSS |
| System monitoring | psutil |

---

## Known Limitations

- Flow feature extraction depends on an external CICFlowMeter installation (WSL or native), configured per machine via environment variables — see the dashboard README for exact setup.
- The model is trained offline on labeled flow data and is not updated from live traffic; live capture only drives inference, not retraining.
- The attack-override threshold is a tunable heuristic on top of raw softmax output, not part of the model itself, and is meant to bias the demo toward flagging suspicious activity rather than to reflect calibrated probability.

---

## Team

Group project (IT/CSE, NITK Surathkal) — four contributors, developed on individual feature branches and merged into `master` after review. See the top of this repository's git history for the branching and commit conventions used during development.
