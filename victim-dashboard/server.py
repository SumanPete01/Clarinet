import os, sys, time, json, pickle, threading, collections, subprocess
from pathlib import Path
import numpy as np
import pandas as pd
import psutil
import torch
import torch.nn as nn
from flask import Flask, render_template, Response, jsonify, request
from flask_cors import CORS

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(BASE_DIR, "..", "transformer", "data", "transformer_model.pth")
SCALER_PATH = os.path.join(BASE_DIR, "..", "transformer", "data", "scaler.pkl")
FLOW_CSV_PATH = os.environ.get("FLOW_CSV_PATH", os.path.join(BASE_DIR, "brute_force_attack.pcap_Flow.csv"))
PCAP_INBOX_DIR = os.environ.get("PCAP_INBOX_DIR", os.path.join(BASE_DIR, "pcap_inbox"))
PCAP_SPOOL_DIR = os.environ.get("PCAP_SPOOL_DIR", os.path.join(BASE_DIR, "pcap_spool"))
FLOW_OUTPUT_DIR = os.environ.get("FLOW_OUTPUT_DIR", os.path.join(BASE_DIR, "flow_outputs"))
PCAP_DONE_DIR = os.environ.get("PCAP_DONE_DIR", os.path.join(BASE_DIR, "pcap_done"))
PCAP_ERROR_DIR = os.environ.get("PCAP_ERROR_DIR", os.path.join(BASE_DIR, "pcap_error"))
PCAP_POLL_SECONDS = float(os.environ.get("PCAP_POLL_SECONDS", "2"))
SPOOL_SETTLE_SECONDS = float(os.environ.get("SPOOL_SETTLE_SECONDS", "10"))
EDITCAP_EXE = os.environ.get("EDITCAP_EXE", "editcap")
PREPARE_SCRIPT_PATH = os.environ.get("PREPARE_SCRIPT_PATH", os.path.join(BASE_DIR, "prepare_flows.py"))
PYTHON_EXE = os.environ.get("PYTHON_EXE", sys.executable)
CICFLOW_WSL_BIN_DIR = os.environ.get(
    "CICFLOW_WSL_BIN_DIR",
    "~/last_try/CICFlowMeter/build/distributions/CICFlowMeter-4.0/bin"
)
CICFLOW_CMD_TEMPLATE = os.environ.get(
    "CICFLOW_CMD_TEMPLATE",
    'wsl -e bash -lc "cd {cicflow_bin} && ./cfm \'{input_wsl}\' \'{output_dir_wsl}\'"'
)

LABEL_NAMES = ["BENIGN", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS slowloris", "FTP-Patator"]
LABEL_COLORS = {
    "BENIGN":        "#10b981",
    "DDoS":          "#ef4444",
    "DoS GoldenEye": "#f97316",
    "DoS Hulk":      "#f97316",
    "DoS slowloris": "#f59e0b",
    "FTP-Patator":   "#8b5cf6",
}

# If any non-benign label reaches this probability (%) or above,
# choose the highest-probability label among those candidates.
ATTACK_OVERRIDE_THRESHOLD_PCT = float(os.environ.get("ATTACK_OVERRIDE_THRESHOLD_PCT", "25"))

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

prepared_feature_df = None
feature_row_index = 0
feature_lock = threading.Lock()
inference_log_every = int(os.environ.get("INFERENCE_LOG_EVERY", "1"))
inference_step = 0

# request counter (updated by Flask)
_req_count  = 0
_req_window = collections.deque()   # timestamps
_req_lock   = threading.Lock()

START_TIME = time.time()

def windows_to_wsl_path(path):
    abs_path = os.path.abspath(path)
    drive, tail = os.path.splitdrive(abs_path)
    drive_letter = drive.rstrip(":").lower()
    tail = tail.replace("\\", "/")
    return f"/mnt/{drive_letter}{tail}"


def load_prepared_feature_rows(prepared_csv_path):
    """Load already prepared CSV (58 features) for transformer inference."""
    global prepared_feature_df, feature_row_index

    if not os.path.exists(prepared_csv_path):
        print(f"Warning: prepared flow CSV not found: {prepared_csv_path}")
        prepared_feature_df = None
        return

    try:
        prepared = pd.read_csv(prepared_csv_path)
        with feature_lock:
            prepared_feature_df = prepared
            feature_row_index = 0
        print(f"Loaded prepared flow features from {prepared_csv_path} | rows={len(prepared_feature_df)}")
        if prepared is not None and not prepared.empty:
            first_two_rows = prepared.head(2).to_dict(orient="records")
            print("First 2 prepared feature rows (post-prepare_flows):")
            print(json.dumps(first_two_rows, indent=2))
    except Exception as ex:
        print(f"Warning: failed to load prepared flow CSV ({prepared_csv_path}): {ex}")
        prepared_feature_df = None


def run_prepare_flows_script(flow_csv_path):
    """Run prepare_flows.py on generated flow CSV and return filtered CSV path."""
    cmd = [
        PYTHON_EXE,
        PREPARE_SCRIPT_PATH,
        "--input-files",
        flow_csv_path,
        "--output-dir",
        FLOW_OUTPUT_DIR,
    ]
    print(f"Running prepare_flows.py: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.strip())
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(f"prepare_flows.py failed (code={result.returncode}): {stderr}")

    filtered_csv_path = os.path.join(FLOW_OUTPUT_DIR, f"{Path(flow_csv_path).stem}_filtered.csv")
    if not os.path.exists(filtered_csv_path):
        raise RuntimeError(f"prepare_flows.py completed but filtered CSV not found: {filtered_csv_path}")

    return filtered_csv_path


def run_cicflowmeter(pcap_path, output_csv_path):
    """Run CICFlowMeter using WSL cfm command template and wait for output CSV."""
    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
    output_dir = os.path.dirname(output_csv_path)
    cmd = CICFLOW_CMD_TEMPLATE.format(
        input=pcap_path,
        output=output_csv_path,
        input_wsl=windows_to_wsl_path(pcap_path),
        output_dir_wsl=windows_to_wsl_path(output_dir) + "/",
        cicflow_bin=CICFLOW_WSL_BIN_DIR,
    )
    print(f"Running CICFlowMeter: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.strip())
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(f"CICFlowMeter failed (code={result.returncode}): {stderr}")

    # cfm writes to output folder and can take a moment to flush file to disk.
    for _ in range(20):
        if os.path.exists(output_csv_path):
            break
        time.sleep(0.5)

    if not os.path.exists(output_csv_path):
        raise RuntimeError(f"CICFlowMeter completed but output CSV not found: {output_csv_path}")

    return output_csv_path


def process_pcap_file(pcap_path):
    pcap_filename = os.path.basename(pcap_path)
    out_csv = os.path.join(FLOW_OUTPUT_DIR, f"{pcap_filename}_Flow.csv")
    print(f"Processing PCAP: {pcap_path}")
    csv_path = run_cicflowmeter(pcap_path, out_csv)
    prepared_csv_path = run_prepare_flows_script(csv_path)
    load_prepared_feature_rows(prepared_csv_path)

    move_pcap_file(pcap_path, PCAP_DONE_DIR, "done")


def move_pcap_file(src_path, target_dir, tag):
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, os.path.basename(src_path))
    try:
        if os.path.exists(target_path):
            os.remove(target_path)
        os.replace(src_path, target_path)
        print(f"Moved PCAP to {tag}: {target_path}")
    except Exception as ex:
        print(f"Warning: could not move PCAP to {tag} folder: {ex}")


def next_inbox_name(source_name):
    cleaned = source_name
    if cleaned.lower().endswith(".part"):
        cleaned = cleaned[:-len(".part")]
    stem = Path(cleaned).stem
    return f"capture_{stem}.pcap"


def spool_capture_candidates(spool_dir):
    files = []
    for name in os.listdir(spool_dir):
        lower = name.lower()
        if lower.endswith(".part") or lower.endswith(".pcap") or lower.endswith(".pcapng"):
            files.append(name)
    return sorted(files)


def convert_spool_to_inbox(source_path, target_path):
    cmd = [EDITCAP_EXE, "-F", "pcap", source_path, target_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(f"editcap failed (code={result.returncode}): {stderr}")


def spool_watch_loop():
    """Convert stable spool captures to pcap and queue them into inbox."""
    os.makedirs(PCAP_SPOOL_DIR, exist_ok=True)
    os.makedirs(PCAP_INBOX_DIR, exist_ok=True)
    os.makedirs(PCAP_ERROR_DIR, exist_ok=True)

    print(f"PCAP spool folder: {PCAP_SPOOL_DIR}")
    print(f"Spool conversion tool: {EDITCAP_EXE}")

    seen_sizes = {}

    while True:
        try:
            now = time.time()
            for name in spool_capture_candidates(PCAP_SPOOL_DIR):
                source_path = os.path.join(PCAP_SPOOL_DIR, name)
                if not os.path.isfile(source_path):
                    continue

                stat_info = os.stat(source_path)
                age = now - stat_info.st_mtime
                if age <= SPOOL_SETTLE_SECONDS:
                    continue

                key = source_path
                size = stat_info.st_size
                prev = seen_sizes.get(key)
                if prev is None or prev[0] != size:
                    seen_sizes[key] = (size, now)
                    continue

                if now - prev[1] < 2:
                    continue

                target_name = next_inbox_name(name)
                target_path = os.path.join(PCAP_INBOX_DIR, target_name)
                suffix = 1
                while os.path.exists(target_path):
                    target_path = os.path.join(PCAP_INBOX_DIR, f"{Path(target_name).stem}_{suffix}.pcap")
                    suffix += 1

                try:
                    convert_spool_to_inbox(source_path, target_path)
                    os.remove(source_path)
                    seen_sizes.pop(key, None)
                    print(f"[SPOOL] converted+queued {name} -> {os.path.basename(target_path)}")
                except Exception as ex:
                    print(f"Warning: failed to convert spool file {source_path}: {ex}")
                    move_pcap_file(source_path, PCAP_ERROR_DIR, "error")
                    seen_sizes.pop(key, None)
        except Exception as ex:
            print(f"Warning: spool watcher error: {ex}")

        time.sleep(PCAP_POLL_SECONDS)


def pcap_watch_loop():
    """Watch inbox for new pcap/pcapng files and feed them through CICFlowMeter."""
    os.makedirs(PCAP_INBOX_DIR, exist_ok=True)
    os.makedirs(FLOW_OUTPUT_DIR, exist_ok=True)
    os.makedirs(PCAP_DONE_DIR, exist_ok=True)
    os.makedirs(PCAP_ERROR_DIR, exist_ok=True)

    print(f"PCAP inbox: {PCAP_INBOX_DIR}")
    print(f"Flow output folder: {FLOW_OUTPUT_DIR}")
    print(f"Processed PCAP folder: {PCAP_DONE_DIR}")
    print(f"Failed PCAP folder: {PCAP_ERROR_DIR}")

    while True:
        try:
            files = []
            for name in os.listdir(PCAP_INBOX_DIR):
                lower = name.lower()
                if lower.endswith(".pcap") or lower.endswith(".pcapng"):
                    files.append(name)

            for name in sorted(files):
                pcap_path = os.path.join(PCAP_INBOX_DIR, name)
                try:
                    process_pcap_file(pcap_path)
                except Exception as ex:
                    print(f"Warning: failed to process {pcap_path}: {ex}")
                    move_pcap_file(pcap_path, PCAP_ERROR_DIR, "error")
        except Exception as ex:
            print(f"Warning: pcap watcher error: {ex}")

        time.sleep(PCAP_POLL_SECONDS)


def next_feature_vector():
    """Return next feature row, its source, and row index for traceable inference logs."""
    global feature_row_index

    with feature_lock:
        if prepared_feature_df is None or prepared_feature_df.empty:
            return np.zeros(58, dtype=np.float32).tolist(), "fallback_zero", -1

        if feature_row_index >= len(prepared_feature_df):
            feature_row_index = 0

        current_idx = feature_row_index
        row = prepared_feature_df.iloc[current_idx].to_numpy(dtype=np.float32)
        feature_row_index += 1
        return row.tolist(), "prepared_flow", current_idx

# ── Inference ──────────────────────────────────────────────────────────────────
def run_inference(feat_vec):
    arr    = np.array(feat_vec, dtype=np.float32).reshape(1, -1)
    arr    = np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=0.0)
    arr    = scaler.transform(arr)
    tensor = torch.tensor(arr, dtype=torch.float32)
    with torch.no_grad():
        logits = model(tensor)
        probs  = torch.softmax(logits, dim=1).squeeze().numpy()
        
    pred_idx = int(np.argmax(probs))

    threshold_candidates = []
    for idx, prob in enumerate(probs):
        label_name = LABEL_NAMES[idx]
        if "benign" in label_name.strip().lower():
            continue
        if float(prob) * 100 >= ATTACK_OVERRIDE_THRESHOLD_PCT:
            threshold_candidates.append(idx)

    if threshold_candidates:
        pred_idx = max(threshold_candidates, key=lambda i: probs[i])

    label       = LABEL_NAMES[pred_idx]
    confidence  = float(probs[pred_idx]) * 100
    return label, confidence, (probs * 100).tolist()

# ── Background Monitor ─────────────────────────────────────────────────────────
def monitor_loop():
    global inference_step

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

        # Use prepared CICFlow rows for inference while keeping dashboard metrics live.
        feat, feat_source, feat_row_idx = next_feature_vector()
        label, conf, probs = run_inference(feat)
        inference_step += 1

        if inference_log_every > 0 and (inference_step % inference_log_every == 0):
            print(
                "[INFER] "
                f"source={feat_source} "
                f"row_idx={feat_row_idx} "
                f"pred={label} "
                f"conf={round(conf, 2)}% "
                f"top2={sorted(zip(LABEL_NAMES, probs), key=lambda x: x[1], reverse=True)[:2]}"
            )

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

if FLOW_CSV_PATH.lower().endswith("_filtered.csv") and os.path.exists(FLOW_CSV_PATH):
    load_prepared_feature_rows(FLOW_CSV_PATH)
threading.Thread(target=spool_watch_loop, daemon=True).start()
threading.Thread(target=pcap_watch_loop, daemon=True).start()
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
