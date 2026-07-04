# Clarinet — Victim Dashboard: Full System Explainer

---

## 1. How the Frontend Works

The frontend is a **single HTML page** (`templates/index.html`) served by Flask.

It has **two data channels**:

```
Browser  ──── GET /  ────────────────────▶  Flask returns index.html
Browser  ──── GET /stream (SSE) ─────────▶  Flask streams JSON every 1 second
```

**SSE (Server-Sent Events)** is the key mechanism. It's like a one-way WebSocket — the server pushes data to the browser over a long-lived HTTP connection. The browser never has to poll.

```
server.py                        index.html (browser)
────────────────────────────     ────────────────────────────
monitor_loop() runs every 1s     const es = new EventSource("/stream")
  → updates `state` dict         es.onmessage = e => { update(JSON.parse(e.data)) }
  → /stream yields JSON  ──────▶  update() rewrites DOM elements live
```

No page refreshes. Everything updates in-place every second.

---

## 2. How We're Using the Model

The model is loaded **once at startup** and runs inference **every second** in the background thread.

```
startup:
  model = TabularTransformer()          ← architecture defined in server.py
  model.load_state_dict(transformer_model.pth)   ← your trained weights
  scaler = pickle.load(scaler.pkl)      ← the StandardScaler from training

every second (monitor_loop):
  1. Read psutil network counters
  2. build_feature_vector(...)  → list of 58 numbers
  3. scaler.transform(feat)     → normalize (same transform as training data)
  4. model(tensor)              → 6 logits
  5. softmax(logits)            → 6 probabilities that sum to 100%
  6. argmax                     → predicted class (0–5 → label name)
  7. update state dict          → SSE pushes to browser
```

**The model never leaves the server.** The browser only ever sees the result (label + probabilities), not the raw inference.

---

## 3. Are We Using JavaScript?

Yes — the frontend uses **vanilla JS only** (no React, no framework).

| What | How |
|------|-----|
| **Chart.js** | Loaded from CDN — draws the live traffic line chart |
| **EventSource API** | Built-in browser API — handles the SSE connection |
| **DOM manipulation** | `document.getElementById(...).textContent = ...` — updates all numbers |
| **CSS animations** | The pulsing dot, the glowing red badge on attack — pure CSS |

No jQuery, no bundler, no npm. It's one `<script>` block at the bottom of the HTML.

---

## 4. What's Being Displayed and What It Means

### Stat Cards (top row)

| Card | Source | What it means |
|------|--------|---------------|
| **Packets In/s** | `psutil.net_io_counters().packets_recv` delta per second | How many IP packets your machine received this second from ALL interfaces |
| **Packets Out/s** | `packets_sent` delta | How many packets your machine sent |
| **Bandwidth In (KB/s)** | `bytes_recv` delta / 1024 | Raw bytes received per second, converted to kilobytes |
| **Bandwidth Out (KB/s)** | `bytes_sent` delta | Raw bytes sent per second |
| **Connections** | `len(psutil.net_connections())` | Total open TCP/UDP sockets on your machine right now |
| **Requests/s** | Flask `before_request` counter | How many HTTP requests hit **this Flask server** specifically in the last 1 second |

### Live Traffic Chart (middle left)

- X-axis: last 60 seconds (each point = 1 second)
- Y-axis left: Packets/s (blue = in, purple = out)
- Y-axis right: Bandwidth KB/s (green dashed)
- Updates by shifting old values off the left and pushing new ones on the right

### ML Detection Panel (middle right)

- **Badge** turns green (🛡️ BENIGN) or red (💀 attack type) based on the model's top prediction
- **Confidence** is the softmax probability of the top class
- **Class Probabilities** — six bars, one per attack class, showing the model's uncertainty
  - If it says BENIGN 52.8% — it's mostly sure but not 100%. This is expected with approximate features.
  - If DDoS bar spikes to 90%+ during an attack → that's the model detecting something

### Server Health (bottom left)

| Gauge | Source |
|-------|--------|
| CPU | `psutil.cpu_percent()` — whole system CPU |
| RAM | `psutil.virtual_memory().percent` — whole system RAM |

### Alert Log (bottom right)

Every time the model predicts anything **other than BENIGN**, a timestamped entry is added. Stored in memory (last 50). Disappears on server restart.

---

## 5. How to Test if Network Statistics Are Proper

Run these in a terminal and compare to what the dashboard shows:

```bash
# Watch packets/bytes per second (like the dashboard does)
watch -n 1 "cat /proc/net/dev | awk 'NR>2 {print \$1, \$3, \$11}'"

# Or with nload (if installed)
nload

# Or with iftop
sudo iftop

# Check active connections count
ss -s   # or
netstat -an | wc -l

# Test requests/s — curl this to see the counter tick up
curl http://localhost:5000/api/ping
```

> If you hammer `curl http://localhost:5000/api/ping` rapidly, you should see the **Requests/s** counter jump on the dashboard immediately.

---

## 6. Code Block-by-Block Explanation

### Block 1 — Paths

```python
MODEL_PATH  = os.path.join(BASE_DIR, "..", "transformer", "data", "transformer_model.pth")
SCALER_PATH = os.path.join(BASE_DIR, "..", "transformer", "data", "scaler.pkl")
```

Navigates relative to `server.py` to find the trained model and scaler in the `transformer/data/` folder.

---

### Block 2 — Model Architecture

```python
class FeatureTokenizer(nn.Module): ...
class TabularTransformer(nn.Module): ...
```

This is a **copy of the exact same architecture** your friend trained. The network structure must be identical — if even one layer is different, `load_state_dict()` will fail. The architecture defines the "shape" of the model; the `.pth` file fills in the learned weights.

---

### Block 3 — Model Loading

```python
model = TabularTransformer().to(device)
model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
model.eval()
```

- `TabularTransformer()` creates the empty model shell
- `load_state_dict(...)` fills it with the trained weights from the `.pth` file
- `model.eval()` turns off dropout and batch norm training mode — critical for inference

---

### Block 4 — Shared State Dict

```python
state = {
    "packets_in": 0.0, "label": "BENIGN", "alert_log": [], ...
}
state_lock = threading.Lock()
```

This is the **single source of truth** shared between the background monitor thread and the Flask SSE endpoint. The lock (`threading.Lock`) prevents race conditions — only one thread can read/write at a time.

---

### Block 5 — Feature Vector Builder

```python
def build_feature_vector(pkt_in, pkt_out, bytes_in, bytes_out, conns, req_s, elapsed):
```

This is the **most important approximation in the system.** The model was trained on **CICIDS-2017 flow-level features** (58 very specific stats about individual TCP/UDP flows). But psutil only gives us system-wide counters.

So we **approximate**:
- `flow_duration` = elapsed time in microseconds
- `fwd_pkts` = packets sent, `bwd_pkts` = packets received
- `fwd_pkt_mean` = bytes_out / packets_out (approximate average packet size)
- `syn_flag` = estimated from requests/s (more requests → more SYNs)
- IAT (Inter-Arrival Time) = flow_duration / packet_count (average gap between packets)
- Everything else is derived from these or approximated to reasonable defaults

> ⚠️ This is intentionally an approximation. It works well enough for a demo. Real production systems would use `scapy` or a dedicated flow exporter to compute exact CICIDS features from actual packet captures (see Q9).

---

### Block 6 — Inference

```python
def run_inference(feat_vec):
    arr = np.array(feat_vec).reshape(1, -1)
    arr = np.nan_to_num(arr, ...)     # sanitize: replace NaN/inf with safe values
    arr = scaler.transform(arr)        # apply same normalization as training
    tensor = torch.tensor(arr, ...)
    with torch.no_grad():
        logits = model(tensor)         # forward pass
        probs  = torch.softmax(logits, dim=1).squeeze().numpy()
    return LABEL_NAMES[argmax], confidence, probs
```

`torch.no_grad()` disables gradient computation — makes inference ~2× faster and saves memory.

---

### Block 7 — Monitor Loop

```python
def monitor_loop():
    prev_net = psutil.net_io_counters()
    prev_time = time.time()
    while True:
        time.sleep(1)
        curr_net = psutil.net_io_counters()
        # compute deltas (diff from last second)
        pkt_in = (curr_net.packets_recv - prev_net.packets_recv) / elapsed
        ...
        feat = build_feature_vector(...)
        label, conf, probs = run_inference(feat)
        with state_lock:
            state[...] = ...   # update shared state
        prev_net = curr_net    # slide the window
```

Runs as a **daemon thread** — dies automatically when the main Flask process exits. Uses a sliding window: always compares "now" vs "1 second ago" to get per-second rates.

---

### Block 8 — SSE Endpoint

```python
@app.route("/stream")
def stream():
    def event_gen():
        while True:
            with state_lock:
                data = json.dumps(dict(state))
            yield f"data: {data}\n\n"   # SSE format requires "data: ...\n\n"
            time.sleep(1)
    return Response(event_gen(), mimetype="text/event-stream")
```

Each browser tab that opens the dashboard opens its own `/stream` connection. Flask handles them in separate threads (because `threaded=True`). The `\n\n` at the end is required by the SSE protocol — the browser's `EventSource` won't fire `onmessage` without it.

---

### Block 9 — Request Counter

```python
@app.before_request
def count_request():
    with _req_lock:
        _req_window.append(time.time())
```

`before_request` runs before **every** Flask route handler. Each request appends its timestamp to a `deque`. The monitor loop then counts how many entries are within the last 1 second — that's the requests/sec metric. Old entries are pruned automatically.

---

## 7. Roadmap: How You Could Attack This

Here's where things get interesting. The dashboard detects attacks using the model — let's see how attacks would manifest:

### Option A — HTTP Flood (simulates DDoS/DoS Hulk)
```
Fire thousands of HTTP requests per second at /api/ping or /api/data
Tools: wrk, ab (Apache Bench), hey, or a custom Python script
```
- `requests/s` spikes → `syn_flag` in feature vector spikes
- `packets_in/out` spikes
- Model should start predicting DDoS or DoS Hulk

### Option B — SYN Flood (TCP-level, simulates DDoS)
```
Send TCP SYN packets without completing the 3-way handshake
Tools: hping3, scapy (requires sudo/root)
sudo hping3 -S --flood -p 5000 <victim-ip>
```
- `connections` explodes (half-open connections pile up)
- High SYN count → model detects DDoS

### Option C — Slowloris (simulates DoS slowloris)
```
Open many connections, send partial HTTP headers very slowly
Tools: slowhttptest, or the "slowloris" Python script
```
- High connection count with very low bandwidth
- Specific pattern of long flow duration + few packets

### Option D — FTP Brute Force simulation (simulates FTP-Patator)
```
Rapid repeated login attempts to any service
Tools: hydra, medusa, or a custom rapid-request script
```

> The key insight: **the model was trained on what these attacks look like as network flows.** When your metrics start looking like those flows, the model should detect them.

---

## 8. Making This Accessible to a Friend on a Different Network

Since your friend is **not on the same LAN**, you need to expose port 5000 to the internet. Here are your options:

### Option A — ngrok (easiest, no firewall changes, recommended for demo)

```bash
# Install ngrok (free tier)
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc
# Or just download from ngrok.com

# Run alongside your Flask server
ngrok http 5000
```

ngrok gives you a public URL like `https://abc123.ngrok.io` — your friend hits that and it tunnels to your local port 5000. **No firewall changes needed.** Free tier has a limit but is fine for demos.

### Option B — Port Forwarding on your router

1. Log into your router admin page (usually `192.168.1.1` or `192.168.0.1`)
2. Find "Port Forwarding" or "NAT"
3. Forward external port `5000` → your local machine's IP (`192.168.0.112`) port `5000`
4. Find your public IP: `curl ifconfig.me`
5. Give your friend: `http://<your-public-ip>:5000`
6. **You may need to temporarily allow port 5000 in your firewall:**
   ```bash
   sudo ufw allow 5000/tcp
   ```

> ⚠️ Port forwarding exposes your machine to the open internet. Use it only for testing and disable it after.

### Option C — Tailscale (VPN mesh, most secure)

```bash
# Both you and your friend install Tailscale (free)
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Tailscale gives both machines a private IP like 100.x.x.x
# Your friend connects to http://100.x.x.x:5000 — fully encrypted
```

No firewall changes, no public exposure, works through NAT. Best for ongoing testing.

---

## 9. Are We Using Flows to Extract Features from Packets?

**Short answer: No. We're approximating.**

Here's the honest breakdown:

| Approach | What we're doing | What we should ideally do |
|----------|-----------------|--------------------------|
| **Current** | `psutil` system-wide counters (bytes/packets sent/received per second for the whole machine) | Per-flow feature extraction |
| **Ideal** | Capture individual TCP/UDP flows and compute exact CICIDS features | ✅ |

**What a "flow" actually means in CICIDS context:**

A flow = all packets between the same IP:port pair in one direction (or both), within a timeout window. Each flow gets features like:
- How long did the flow last? (Flow Duration)
- What's the average time between packets? (IAT = Inter-Arrival Time)
- How big were the packets? (Packet Length Mean/Std)
- Were there SYN/ACK/FIN flags? (Flag Counts)

**To extract real CICIDS features from live traffic you'd need:**

```
Option 1: scapy (pure Python packet capture)
  - sudo required
  - sniff() captures raw packets
  - You group by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
  - Compute stats per flow per time window

Option 2: CICFlowMeter (the actual tool used to generate CICIDS-2017)
  - Java tool that processes pcap files or live interfaces
  - Outputs exactly the right CSV format

Option 3: pyshark / tshark (Wireshark's CLI)
  - sudo required
  - Good for offline pcap analysis
```

**Why we didn't do this for the demo:**

1. `scapy` requires `sudo` — Flask servers shouldn't run as root
2. Real flow extraction needs a 5-60 second window to compute IAT stats properly — makes the demo sluggish
3. psutil approximation is good enough to demonstrate the concept

**The demo still works because:**
- When traffic spikes (DDoS), psutil metrics spike too
- The approximate feature vector shifts toward attack distributions
- The model picks up on those shifts

If you wanted production accuracy, you'd run `scapy` as a separate root process, pipe flow features into the Flask server via a queue, and feed those to the model instead.
