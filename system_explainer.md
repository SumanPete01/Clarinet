# Clarinet — Victim Dashboard: Full System Explainer

> **This document supersedes the old version.** The system previously ran inference on *approximated* features built from `psutil` system counters (packets/sec, bytes/sec, etc. treated as stand-ins for flow statistics). That approximation layer (`build_feature_vector`) has been **removed**. The system now captures **real packets off the wire**, reconstructs **real network flows** with CICFlowMeter, and runs the transformer on the **real 58 CICIDS-style features** computed from that traffic. What follows describes the system as it actually works today.

---

## 1. The Real Pipeline, End to End

```
tshark (live capture on the wire)
        │  writes rolling .pcap files
        ▼
   pcap_spool/                     ← raw captures land here
        │  spool_watch_loop() in server.py waits for the file to
        │  stop growing, then normalizes it with `editcap -F pcap`
        ▼
   pcap_inbox/                     ← queued, normalized .pcap files
        │  pcap_watch_loop() in server.py picks these up
        │  runs CICFlowMeter (via WSL or native binary)
        ▼
   flow_outputs/*_Flow.csv         ← real per-flow statistics
        │  (Flow Duration, IAT stats, flag counts, packet length
        │   stats, etc. — computed by CICFlowMeter from the actual
        │   packets, not estimated)
        │  prepare_flows.py reorders/renames columns to match the
        │  exact 58-feature schema the model was trained on
        ▼
   flow_outputs/*_filtered.csv     ← model-ready feature rows
        │  loaded into memory by server.py
        ▼
   Transformer model (transformer_model.pth)
        │  StandardScaler → forward pass → softmax
        ▼
   Live prediction + confidence + per-class probabilities
        │
        ▼
   Flask SSE (/stream) → browser dashboard, updated every second
```

Every stage is driven by files actually produced by `tshark`, `editcap`, and CICFlowMeter — there is no synthetic or estimated feature vector anywhere in this path anymore.

---

## 2. How the Frontend Works

The frontend is a **single HTML page** (`templates/index.html`) served by Flask, unchanged in mechanism from before:

```
Browser  ──── GET /            ────────────────────▶  Flask returns index.html
Browser  ──── GET /stream (SSE) ───────────────────▶  Flask streams JSON every 1 second
```

**SSE (Server-Sent Events)** is the transport. The server pushes a JSON snapshot of shared state to the browser once a second over a long-lived HTTP connection — no polling, no page refresh.

```
server.py                        index.html (browser)
────────────────────────────     ────────────────────────────
monitor_loop() runs every 1s     const es = new EventSource("/stream")
  → updates `state` dict         es.onmessage = e => { update(JSON.parse(e.data)) }
  → /stream yields JSON  ──────▶  update() rewrites DOM elements live
```

---

## 3. How We're Using the Model Now

The model is loaded **once at startup** and runs inference **every second** in a background thread — but the input it receives has changed completely.

```
startup:
  model  = TabularTransformer()                    ← architecture defined in server.py
  model.load_state_dict(transformer_model.pth)     ← trained weights
  scaler = pickle.load(scaler.pkl)                 ← StandardScaler from training

background (spool_watch_loop + pcap_watch_loop):
  1. Watch pcap_spool/ for new capture files, normalize with editcap
  2. Watch pcap_inbox/ for normalized pcaps
  3. Run CICFlowMeter on each pcap → *_Flow.csv (real flow features)
  4. Run prepare_flows.py → *_filtered.csv (58 columns, model schema)
  5. Load the filtered CSV into memory as `prepared_feature_df`

every second (monitor_loop):
  1. next_feature_vector() pulls the next row from prepared_feature_df
     (falls back to a zero-vector only if no real flow data has been
     processed yet — this is a genuine "no data yet" fallback, not a
     substitute feature source)
  2. scaler.transform(row)      → normalize with the training-time scaler
  3. model(tensor)               → 6 logits
  4. softmax(logits)             → 6 class probabilities
  5. attack-override threshold   → if any attack class ≥ threshold%,
                                    prefer it over a low-margin BENIGN call
  6. update shared state         → SSE pushes it to the browser
```

**Key change from before:** the feature vector is no longer built from `psutil` counters. It is a row of real CICFlowMeter output — actual flow duration, actual inter-arrival times, actual TCP flag counts, actual packet length statistics — computed from packets captured live on the wire.

`psutil` is still used, but only for the dashboard's system-health and traffic-rate widgets (see below), and it no longer feeds the model at all.

---

## 4. Are We Using JavaScript?

Yes — vanilla JS only, no framework, no build step:

| What | How |
|------|-----|
| **Chart.js** | Loaded from CDN — draws the live traffic line chart |
| **EventSource API** | Built-in browser API — handles the SSE connection |
| **DOM manipulation** | `document.getElementById(...).textContent = ...` — updates all numbers |
| **CSS animations** | The pulsing status dot, the glowing attack badge — pure CSS |

---

## 5. What's Being Displayed and What It Means

### Stat Cards (top row) — still system-level, for context

These reflect the host's overall network activity and are **not** what the model sees; they give a human-readable sense of "is a lot of traffic happening right now."

| Card | Source | What it means |
|------|--------|---------------|
| **Packets In/s** | `psutil.net_io_counters().packets_recv` delta per second | Packets received by the host this second, all interfaces |
| **Packets Out/s** | `packets_sent` delta | Packets sent by the host |
| **Bandwidth In (KB/s)** | `bytes_recv` delta / 1024 | Bytes received per second |
| **Bandwidth Out (KB/s)** | `bytes_sent` delta | Bytes sent per second |
| **Connections** | `len(psutil.net_connections())` | Open TCP/UDP sockets on the host right now |
| **Requests/s** | Flask `before_request` counter | HTTP requests hitting this Flask server specifically, last 1 second |

### Live Traffic Chart (middle left)

- X-axis: last 60 seconds. Y-axis left: packets/s (in/out). Y-axis right: bandwidth KB/s.
- Same host-level counters as the stat cards, plotted over time.

### ML Detection Panel (middle right) — driven by real flow data

- **Badge**: green (BENIGN) or red (attack type), based on the model's prediction on the most recent real captured flow.
- **Confidence**: softmax probability of the winning class, after the attack-override threshold is applied.
- **Class Probabilities**: all six class scores, reflecting the model's view of the actual captured flow — not an estimate.

### Server Health (bottom left)

| Gauge | Source |
|-------|--------|
| CPU | `psutil.cpu_percent()` — whole-system CPU |
| RAM | `psutil.virtual_memory().percent` — whole-system RAM |

### Alert Log (bottom right)

Every non-BENIGN prediction is appended with a timestamp. Kept in memory, last 50 entries, cleared on restart.

---

## 6. Verifying the Capture Pipeline Is Actually Working

Rather than checking psutil counters against `nload`/`iftop` (which only proves system-level counting is correct), verify the **real capture chain**:

```powershell
# 1. Confirm tshark is capturing into the spool
Get-ChildItem .\pcap_spool | Select-Object Name,Length,LastWriteTime

# 2. Confirm normalized files are reaching the inbox
Get-ChildItem .\pcap_inbox | Select-Object Name,Length,LastWriteTime

# 3. Confirm CICFlowMeter is producing real flow CSVs
Get-ChildItem .\flow_outputs | Select-Object Name,Length,LastWriteTime

# 4. Confirm successfully processed captures
Get-ChildItem .\pcap_done | Select-Object Name,Length,LastWriteTime

# 5. Confirm nothing is silently failing
Get-ChildItem .\pcap_error | Select-Object Name,Length,LastWriteTime
```

In the server console, watch for:

- `Loaded prepared flow features from ... | rows=N` — real flow rows were loaded
- `[INFER] source=prepared_flow row_idx=... pred=...` — inference is running on real flow data

If you instead see `source=fallback_zero`, no real flow CSV has been loaded yet (e.g. capture pipeline hasn't produced output, or CICFlowMeter/editcap paths are misconfigured) — the model is temporarily receiving a zero-vector placeholder, not a "system approximation." This is a data-availability gap, not a design choice.

---

## 7. Code Block-by-Block (Current `server.py`)

### Block 1 — Paths & Pipeline Config

```python
MODEL_PATH  = .../transformer/data/transformer_model.pth
SCALER_PATH = .../transformer/data/scaler.pkl
PCAP_SPOOL_DIR, PCAP_INBOX_DIR, FLOW_OUTPUT_DIR, PCAP_DONE_DIR, PCAP_ERROR_DIR
CICFLOW_WSL_BIN_DIR, CICFLOW_CMD_TEMPLATE, EDITCAP_EXE
```

All the folders and external-tool paths that drive the real capture-to-features pipeline. These are environment-variable overridable per machine (see `victim-dashboard/README.md`).

### Block 2 — Model Architecture

```python
class FeatureTokenizer(nn.Module): ...
class TabularTransformer(nn.Module): ...
```

Unchanged: this must stay bit-for-bit identical to the architecture used in `train.py`, or `load_state_dict()` fails.

### Block 3 — Model & Scaler Loading

```python
model = TabularTransformer().to(device)
model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
model.eval()
```

Loads trained weights once at startup; `eval()` disables dropout/batchnorm training behavior for inference.

### Block 4 — Shared State Dict

```python
state = { "packets_in": 0.0, ..., "label": "BENIGN", "alert_log": [], ... }
state_lock = threading.Lock()
```

Single source of truth shared between the capture/inference threads and the Flask SSE endpoint, protected by a lock.

### Block 5 — Spool Watcher (`spool_watch_loop`)

Watches `pcap_spool/` for files written by `tshark`, waits for them to stop growing (`SPOOL_SETTLE_SECONDS`), converts them to clean `.pcap` with `editcap`, and queues them into `pcap_inbox/`. Failed conversions move to `pcap_error/`.

### Block 6 — PCAP Watcher (`pcap_watch_loop` → `process_pcap_file`)

Watches `pcap_inbox/`, and for each file:
1. Runs CICFlowMeter (`run_cicflowmeter`) → real per-flow CSV in `flow_outputs/`.
2. Runs `prepare_flows.py` (`run_prepare_flows_script`) → 58-column filtered CSV matching the training schema.
3. Loads the filtered CSV into `prepared_feature_df` (`load_prepared_feature_rows`).
4. Moves the source pcap to `pcap_done/` (or `pcap_error/` on failure).

### Block 7 — Feature Row Selection (`next_feature_vector`)

```python
def next_feature_vector():
    if prepared_feature_df is None or empty:
        return zeros(58), "fallback_zero", -1
    row = prepared_feature_df.iloc[feature_row_index]
    feature_row_index += 1
    return row, "prepared_flow", current_idx
```

Steps through real captured-flow rows in order, one per inference tick, wrapping around once exhausted. This is the direct replacement for the old psutil-based `build_feature_vector` approximation — the old function no longer exists in this codebase.

### Block 8 — Inference (`run_inference`)

```python
arr    = scaler.transform(feat_vec)
tensor = torch.tensor(arr)
logits = model(tensor)
probs  = softmax(logits)
```

Same as before, but `feat_vec` now originates from real flow data, not synthetic system counters. An attack-override threshold (`ATTACK_OVERRIDE_THRESHOLD_PCT`) then picks the strongest non-benign class if it clears a configurable probability floor, biasing the demo toward flagging suspicious activity.

### Block 9 — Monitor Loop (`monitor_loop`)

Runs every second: computes host-level psutil deltas for the dashboard's display cards, pulls the next real flow row via `next_feature_vector()`, runs inference, and writes both into `state` under `state_lock`. Non-BENIGN predictions are also appended to the alert log.

### Block 10 — SSE Endpoint (`/stream`)

```python
@app.route("/stream")
def stream():
    def event_gen():
        while True:
            data = json.dumps(dict(state))
            yield f"data: {data}\n\n"
            time.sleep(1)
    return Response(event_gen(), mimetype="text/event-stream")
```

Streams the shared state to the browser once per second. Unchanged mechanism.

### Block 11 — Request Counter

```python
@app.before_request
def count_request():
    _req_window.append(time.time())
```

Feeds the "Requests/s" stat card — purely a Flask-level HTTP counter, unrelated to model input.

---

## 8. Generating Real Attack Traffic

Because inference now runs on **actual captured packets**, running an attack tool against the victim's port and capturing it with `tshark` produces a **genuine flow** for CICFlowMeter to process — not a simulated feature vector.

### Option A — HTTP Flood (`traffic_attack.py`, included in this repo)
```bash
python traffic_attack.py --target http://<victim-ip>:5000 --workers 20 --duration 60
```
Hits `/`, `/api/ping`, `/api/data` concurrently from multiple worker threads. Produces real high-rate flows that CICFlowMeter will characterize with short IATs, high packet counts, and elevated SYN/ACK activity — the same signature the model was trained to recognize as DoS Hulk/DDoS-like traffic.

### Option B — SYN Flood (simulates DDoS)
```bash
sudo hping3 -S --flood -p 5000 <victim-ip>
```
Real half-open TCP connections, captured and turned into real flow features by CICFlowMeter.

### Option C — Slowloris (simulates DoS slowloris)
Long-lived, slow, partial-header connections — captured the same way, producing flows with long duration and low packet counts.

### Option D — FTP/Login Brute Force (simulates FTP-Patator)
Rapid repeated connection attempts, captured and processed identically.

In every case, the workflow is the same: run the attack → `tshark` captures it into `pcap_spool/` → the pipeline turns it into real flow features → the model classifies the actual traffic that occurred.

---

## 9. Exposing the Dashboard to a Remote Attacker Machine

Unchanged from before — three options depending on setup convenience vs. security:

- **ngrok** — `ngrok http 5000`, easiest for a demo, no firewall changes.
- **Router port forwarding** — forward external port 5000 to the victim machine's LAN IP; requires a firewall rule (`sudo ufw allow 5000/tcp`) and exposes the machine publicly.
- **Tailscale** — private mesh VPN, no public exposure, recommended for repeated testing.

---

## 10. Are We Using Real Flows to Extract Features from Packets?

**Yes.** This is the core change from the previous version of this document.

| Approach | Status |
|----------|--------|
| ~~psutil system-wide counters approximating flow stats~~ | **Removed** |
| **CICFlowMeter computing real per-flow features from captured pcaps** | **Current implementation** |

A flow = all packets between the same IP:port pair (one or both directions) within a timeout window. CICFlowMeter groups captured packets into flows and computes the exact CICIDS-2017-style feature set the model expects: Flow Duration, Inter-Arrival Times (mean/std/max/min, forward and backward), packet length statistics, TCP flag counts, header lengths, active/idle timing, and more — the full 58-column schema in `prepare_flows.py`'s `KEEP_COLUMNS`.

**Current pipeline in full:**

```
tshark  → raw packets on disk (pcap_spool/)
editcap → normalized pcap (pcap_inbox/)
CICFlowMeter → real flow statistics (flow_outputs/*_Flow.csv)
prepare_flows.py → reordered/renamed to the training schema (*_filtered.csv)
model → real prediction on real traffic
```

`prepare_flows.py` also handles schema drift between CICFlowMeter versions (its `KNOWN_MAPPINGS` and fuzzy column matching via `get_close_matches`), so minor naming differences in CICFlowMeter's output don't break the feature alignment — but the underlying values are always computed from actual packets, never estimated.

**Why this matters for accuracy:** the model was trained on CICIDS-2017 flow features. Feeding it real flow features computed the same way (rather than a system-level approximation) means the input distribution at inference time actually matches what the model learned from — closing the gap that the old psutil-based approach openly acknowledged as a limitation.
