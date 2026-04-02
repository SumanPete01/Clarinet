import os, sys, time, json, pickle, threading, collections
import numpy as np
import psutil
import torch
import torch.nn as nn
from flask import Flask, render_template, Response, jsonify, request
from flask_cors import CORS

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(BASE_DIR, "..", "transformer", "data", "transformer_model.pth")
SCALER_PATH = os.path.join(BASE_DIR, "..", "transformer", "data", "scaler.pkl")

LABEL_NAMES = ["BENIGN", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS slowloris", "FTP-Patator"]
LABEL_COLORS = {
    "BENIGN":        "#10b981",
    "DDoS":          "#ef4444",
    "DoS GoldenEye": "#f97316",
    "DoS Hulk":      "#f97316",
    "DoS slowloris": "#f59e0b",
    "FTP-Patator":   "#8b5cf6",
}

# ── Model Architecture ─────────────────────────────────────────────────────────
class FeatureTokenizer(nn.Module):
    def __init__(self, num_features, d_model):
        super().__init__()
        self.value_projection  = nn.Linear(1, d_model)
        self.feature_embedding = nn.Parameter(torch.randn(num_features, d_model))

    def forward(self, x):
        x = x.unsqueeze(-1)
        x = self.value_projection(x)
        x = x + self.feature_embedding
        return x

class TabularTransformer(nn.Module):
    def __init__(self, num_features=58, num_classes=6, d_model=64, n_heads=4, depth=2, dropout=0.1):
        super().__init__()
        self.tokenizer   = FeatureTokenizer(num_features, d_model)
        encoder_layer    = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=n_heads,
            dim_feedforward=d_model * 4,
            dropout=dropout, batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=depth)
        self.cls_token   = nn.Parameter(torch.randn(1, 1, d_model))
        self.classifier  = nn.Sequential(
            nn.LayerNorm(d_model),
            nn.Linear(d_model, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, num_classes)
        )

    def forward(self, x):
        b = x.size(0)
        x = self.tokenizer(x)
        cls = self.cls_token.expand(b, -1, -1)
        x   = torch.cat((cls, x), dim=1)
        x   = self.transformer(x)
        return self.classifier(x[:, 0])

# ── Load Model & Scaler ────────────────────────────────────────────────────────
device = torch.device("cpu")
print("Loading model and scaler...")
model = TabularTransformer().to(device)
model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
model.eval()

with open(SCALER_PATH, "rb") as f:
    scaler = pickle.load(f)
print("✅ Model ready.")

# ── Shared State ───────────────────────────────────────────────────────────────
state = {
    "packets_in":   0.0,
    "packets_out":  0.0,
    "bytes_in":     0.0,
    "bytes_out":    0.0,
    "connections":  0,
    "requests_sec": 0.0,
    "label":        "BENIGN",
    "confidence":   100.0,
    "probabilities": [100.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    "cpu":          0.0,
    "ram":          0.0,
    "uptime":       0,
    "alert_log":    [],        # [{time, label, confidence}]
}
state_lock  = threading.Lock()

# request counter (updated by Flask)
_req_count  = 0
_req_window = collections.deque()   # timestamps
_req_lock   = threading.Lock()

START_TIME = time.time()

# ── Feature Construction from psutil ──────────────────────────────────────────
def build_feature_vector(pkt_in, pkt_out, bytes_in, bytes_out, conns, req_s, elapsed=1.0):
    """
    Approximate the 58 CICIDS flow features from available system metrics.
    Rough mapping — good enough for live demo.
    """
    flow_dur      = max(int(elapsed * 1e6), 1)
    fwd_pkts      = max(int(pkt_out), 0)
    bwd_pkts      = max(int(pkt_in),  0)
    fwd_bytes     = max(int(bytes_out), 0)
    bwd_bytes     = max(int(bytes_in),  0)

    fwd_pkt_mean  = fwd_bytes / max(fwd_pkts, 1)
    bwd_pkt_mean  = bwd_bytes / max(bwd_pkts, 1)
    fwd_pkt_std   = fwd_pkt_mean * 0.3
    bwd_pkt_std   = bwd_pkt_mean * 0.3
    fwd_pkt_max   = int(fwd_pkt_mean * 1.5)
    fwd_pkt_min   = int(fwd_pkt_mean * 0.5)
    bwd_pkt_max   = int(bwd_pkt_mean * 1.5)
    bwd_pkt_min   = int(bwd_pkt_mean * 0.5)

    total_pkts    = max(fwd_pkts + bwd_pkts, 1)
    flow_bytes_s  = (fwd_bytes + bwd_bytes) / elapsed
    flow_pkts_s   = total_pkts / elapsed

    iat_base      = flow_dur / max(total_pkts, 1)          # mean IAT (µs)
    fwd_iat_mean  = flow_dur / max(fwd_pkts, 1)
    bwd_iat_mean  = flow_dur / max(bwd_pkts, 1)

    pkt_len_mean  = (fwd_bytes + bwd_bytes) / total_pkts
    pkt_len_std   = pkt_len_mean * 0.25
    pkt_len_min   = int(pkt_len_mean * 0.4)
    pkt_len_max   = int(pkt_len_mean * 1.8)

    # SYN flag estimate: lots of SYN = SYN flood / DDoS
    syn_flag  = min(int(req_s * 2), 200)
    ack_flag  = int(fwd_pkts * 0.7)
    psh_flag  = int(fwd_pkts * 0.3)
    fin_flag  = int(conns * 0.1)
    rst_flag  = 0
    urg_flag  = 0
    cwe_flag  = 0
    ece_flag  = 0

    down_up   = bwd_pkts / max(fwd_pkts, 1)

    init_win_fwd = 8192
    init_win_bwd = 8192
    act_data_fwd = max(fwd_pkts - 2, 0)
    min_seg      = 20

    active_mean = max(flow_dur * 0.6, 0)
    active_std  = active_mean * 0.2
    active_max  = int(active_mean * 1.4)
    active_min  = int(active_mean * 0.6)
    idle_mean   = max(flow_dur * 0.4, 0)
    idle_std    = idle_mean * 0.2
    idle_max    = int(idle_mean * 1.4)
    idle_min    = int(idle_mean * 0.6)

    return [
        flow_dur, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes,
        fwd_pkt_max, fwd_pkt_min, fwd_pkt_mean, fwd_pkt_std,
        bwd_pkt_max, bwd_pkt_min, bwd_pkt_mean, bwd_pkt_std,
        flow_bytes_s, flow_pkts_s,
        iat_base, iat_base * 0.3, iat_base * 2, 0,
        flow_dur, fwd_iat_mean, fwd_iat_mean * 0.3, fwd_iat_mean * 2, 0,
        flow_dur, bwd_iat_mean, bwd_iat_mean * 0.3, bwd_iat_mean * 2, 0,
        0, 0,                                  # Fwd PSH / URG flags
        fwd_pkts * 20, bwd_pkts * 20,          # Header lengths
        pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std,
        fin_flag, syn_flag, rst_flag, psh_flag, ack_flag, urg_flag, cwe_flag, ece_flag,
        down_up,
        init_win_fwd, init_win_bwd, act_data_fwd, min_seg,
        active_mean, active_std, active_max, active_min,
        idle_mean, idle_std, idle_max, idle_min,
    ]

# ── Inference ──────────────────────────────────────────────────────────────────
def run_inference(feat_vec):
    arr    = np.array(feat_vec, dtype=np.float32).reshape(1, -1)
    arr    = np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=0.0)
    arr    = scaler.transform(arr)
    tensor = torch.tensor(arr, dtype=torch.float32)
    with torch.no_grad():
        logits = model(tensor)
        probs  = torch.softmax(logits, dim=1).squeeze().numpy()
    pred_idx    = int(np.argmax(probs))
    label       = LABEL_NAMES[pred_idx]
    confidence  = float(probs[pred_idx]) * 100
    return label, confidence, (probs * 100).tolist()

# ── Background Monitor ─────────────────────────────────────────────────────────
def monitor_loop():
    prev_net = psutil.net_io_counters()
    prev_time = time.time()

    while True:
        time.sleep(1)
        now      = time.time()
        elapsed  = now - prev_time
        curr_net = psutil.net_io_counters()

        pkt_in   = (curr_net.packets_recv - prev_net.packets_recv) / elapsed
        pkt_out  = (curr_net.packets_sent - prev_net.packets_sent) / elapsed
        bytes_in = (curr_net.bytes_recv   - prev_net.bytes_recv)   / elapsed
        bytes_out= (curr_net.bytes_sent   - prev_net.bytes_sent)   / elapsed
        conns    = len(psutil.net_connections())

        # requests/sec from tracked window
        cutoff = now - 1.0
        with _req_lock:
            while _req_window and _req_window[0] < cutoff:
                _req_window.popleft()
            req_s = len(_req_window)

        # Build feature vector & infer
        feat   = build_feature_vector(pkt_in, pkt_out, bytes_in, bytes_out, conns, req_s, elapsed)
        label, conf, probs = run_inference(feat)

        uptime = int(now - START_TIME)
        cpu    = psutil.cpu_percent()
        ram    = psutil.virtual_memory().percent

        with state_lock:
            state["packets_in"]    = round(pkt_in, 1)
            state["packets_out"]   = round(pkt_out, 1)
            state["bytes_in"]      = round(bytes_in / 1024, 2)      # KB/s
            state["bytes_out"]     = round(bytes_out / 1024, 2)
            state["connections"]   = conns
            state["requests_sec"]  = req_s
            state["label"]         = label
            state["confidence"]    = round(conf, 1)
            state["probabilities"] = [round(p, 2) for p in probs]
            state["cpu"]           = cpu
            state["ram"]           = ram
            state["uptime"]        = uptime

            if label != "BENIGN":
                state["alert_log"].insert(0, {
                    "time":       time.strftime("%H:%M:%S"),
                    "label":      label,
                    "confidence": round(conf, 1),
                })
                state["alert_log"] = state["alert_log"][:50]   # keep 50 most recent

        prev_net  = curr_net
        prev_time = now

threading.Thread(target=monitor_loop, daemon=True).start()

# ── Flask App ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

@app.before_request
def count_request():
    with _req_lock:
        _req_window.append(time.time())

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/state")
def api_state():
    with state_lock:
        return jsonify(dict(state))

@app.route("/stream")
def stream():
    """SSE endpoint — pushes state every second."""
    def event_gen():
        while True:
            with state_lock:
                data = json.dumps(dict(state))
            yield f"data: {data}\n\n"
            time.sleep(1)
    return Response(event_gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})

# Dummy endpoints so the "victim" server has something to attack
@app.route("/api/ping")
def ping():
    return jsonify({"status": "ok", "timestamp": time.time()})

@app.route("/api/data")
def data():
    return jsonify({"payload": "x" * 512, "timestamp": time.time()})

if __name__ == "__main__":
    print("Victim server running at http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, threaded=True, debug=False)
