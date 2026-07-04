# Victim Dashboard Pipeline Guide (Current)

This guide matches the current implementation where only `server.py` is required.

Pipeline flow:

1. Capture packets into `pcap_spool/`
2. `server.py` automatically converts spool files to real pcap using `editcap`
3. Converted files are queued into `pcap_inbox/`
4. `server.py` runs CICFlowMeter on inbox files
5. `prepare_flows.py` creates ordered 58-feature CSV
6. Transformer inference runs on prepared rows

---

## 1) Folder Roles

- `pcap_spool/`
  - raw capture files land here (`.pcap`, `.pcapng`, or `.part`)
- `pcap_inbox/`
  - normalized `.pcap` files queued for CICFlowMeter
- `flow_outputs/`
  - CICFlow output (`*_Flow.csv`) and prepared output (`*_filtered.csv`)
- `pcap_done/`
  - successfully processed pcaps
- `pcap_error/`
  - failed conversions/processing

---

## 2) Your Current Recommended Setup (Windows)

You use two terminals on the victim machine.

### Terminal 1: Run Flask + full processing pipeline

```powershell
cd D:\Clarinet_testing\Clarinet\victim-dashboard
python .\server.py
```

### Terminal 2: Capture traffic on port 5000 into spool

```powershell
tshark -i 5 -f "tcp port 5000" -b duration:15 -b files:200 -w "D:\Clarinet_testing\Clarinet\victim-dashboard\pcap_spool\cap.pcap"
```

Notes:

- Replace `-i 5` with your Wi-Fi/NIC interface index from `tshark -D`.
- Keep this terminal running while attacker traffic is sent from a second machine.

---

## 3) What Happens Automatically in `server.py`

No separate mover script is needed now.

1. `spool_watch_loop` watches `pcap_spool/`
2. Waits for file to settle (`SPOOL_SETTLE_SECONDS`)
3. Runs `editcap -F pcap` and writes into `pcap_inbox/`
4. `pcap_watch_loop` picks inbox pcaps
5. Runs CICFlowMeter -> writes `*_Flow.csv`
6. Runs `prepare_flows.py` -> writes `*_filtered.csv`
7. Loads prepared rows for transformer inference

---

## 4) Required Tools (Windows Host)

Install and verify:

1. Python dependencies (Flask, torch, pandas, etc. for `server.py`)
2. Wireshark/TShark tools (`tshark`, `editcap`)
3. CICFlowMeter runtime

`editcap` must be available on PATH, or you must set `EDITCAP_EXE`.

---

## 5) Environment Variables You May Need to Change

These are read by `server.py`.

### A) Works with WSL-based CICFlowMeter (default style)

- `CICFLOW_WSL_BIN_DIR`
  - path to your CICFlowMeter `bin` in WSL
- `CICFLOW_CMD_TEMPLATE`
  - default uses `wsl -e bash -lc ...`

### B) If teammate does not have WSL

Set command template to native Windows command and avoid WSL placeholders.

PowerShell example:

```powershell
$env:CICFLOW_CMD_TEMPLATE='cicflowmeter -f "{input}" -c "{output}"'
```

If `cicflowmeter` is not on PATH, provide full executable path:

```powershell
$env:CICFLOW_CMD_TEMPLATE='"C:\path\to\cicflowmeter.exe" -f "{input}" -c "{output}"'
```

### C) If `editcap` is not on PATH

```powershell
$env:EDITCAP_EXE='C:\Program Files\Wireshark\editcap.exe'
```

### D) Optional threshold tuning for attack override

```powershell
$env:ATTACK_OVERRIDE_THRESHOLD_PCT='25'
```

---

## 6) Fast Reset

From `victim-dashboard`:

```powershell
python .\reset_pipeline.py --yes
```

---

## 7) Quick Verification Commands

```powershell
Get-ChildItem .\pcap_spool | Select-Object Name,Length,LastWriteTime
Get-ChildItem .\pcap_inbox | Select-Object Name,Length,LastWriteTime
Get-ChildItem .\flow_outputs | Select-Object Name,Length,LastWriteTime
Get-ChildItem .\pcap_done | Select-Object Name,Length,LastWriteTime
Get-ChildItem .\pcap_error | Select-Object Name,Length,LastWriteTime
```

Inference confirmation logs to look for in Terminal 1:

- `Loaded prepared flow features from ...`
- `[INFER] source=prepared_flow row_idx=... pred=...`

If you see `source=fallback_zero`, prepared rows are not loaded yet.

---

## 8) Typical Failure Causes

1. Files go to `pcap_error/`
   - `editcap` missing
   - CICFlow command failed
   - invalid/empty capture

2. No files in `flow_outputs/`
   - `pcap_inbox/` not getting files
   - CICFlow command/path not valid

3. No packets captured
   - wrong interface index in tshark command
   - traffic not reaching victim machine

---

## 9) Team Note

Project-relative folders are same for everyone under `Clarinet/victim-dashboard`.
Machine-specific setup each teammate must adjust:

1. NIC index for `tshark -i <index>`
2. `CICFLOW_CMD_TEMPLATE` (WSL vs non-WSL)
3. `CICFLOW_WSL_BIN_DIR` if using WSL
4. `EDITCAP_EXE` if not in PATH

---

## 10) CICFlowMeter Install Guide (WSL, From Scratch)

Use this if teammate has no CICFlowMeter yet.

1. Clone source:

```bash
cd ~
git clone https://github.com/ISCX/CICFlowMeter.git
cd CICFlowMeter
```

2. Install Java 8 (required by old build):

```bash
sudo apt update
sudo apt install -y openjdk-8-jdk maven unzip
sudo update-alternatives --config java
sudo update-alternatives --config javac
java -version
```

3. Verify jnetpcap files exist:

```bash
ls jnetpcap/linux/jnetpcap-1.4.r1425
```

Expected files include `jnetpcap.jar` and `libjnetpcap.so`.

4. Install jnetpcap jar in local Maven repo:

```bash
mvn install:install-file \
  -Dfile=jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar \
  -DgroupId=org.jnetpcap \
  -DartifactId=jnetpcap \
  -Dversion=1.4.1 \
  -Dpackaging=jar
```

5. Export native library path (use your actual path):

```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$HOME/CICFlowMeter/jnetpcap/linux/jnetpcap-1.4.r1425
```

6. Build CICFlowMeter:

```bash
cd ~/CICFlowMeter
chmod +x gradlew
./gradlew clean build || ./gradlew assemble
./gradlew distZip
```

7. Extract distribution:

```bash
cd ~/CICFlowMeter/build/distributions
unzip -o CICFlowMeter-4.0.zip || jar -xvf CICFlowMeter-4.0.zip
cd CICFlowMeter-4.0/bin
chmod +x cfm
```

8. Quick test run:

```bash
sudo ./cfm "/path/to/input.pcap" "/path/to/output_dir/"
```

After success, CSV files are generated in output directory.

---

## 11) Exact CIC Locations To Configure In This Project

These are the only places that matter for CICFlow paths/commands.

In `server.py`:

1. `CICFLOW_WSL_BIN_DIR`
  - default points to a personal path (`~/last_try/...`) and should be changed per machine.

2. `CICFLOW_CMD_TEMPLATE`
  - controls how CICFlowMeter is invoked.
  - WSL default uses `wsl -e bash -lc ...`.

3. `windows_to_wsl_path(...)`
  - used only when command template expects WSL paths (`/mnt/...`).

Recommended teammate setup:

### If using WSL CICFlowMeter

```powershell
$env:CICFLOW_WSL_BIN_DIR="~/CICFlowMeter/build/distributions/CICFlowMeter-4.0/bin"
$env:CICFLOW_CMD_TEMPLATE='wsl -e bash -lc "cd {cicflow_bin} && ./cfm ''{input_wsl}'' ''{output_dir_wsl}''"'
```

### If not using WSL (native Windows CICFlow command)

```powershell
$env:CICFLOW_CMD_TEMPLATE='cicflowmeter -f "{input}" -c "{output}"'
```

or with full path:

```powershell
$env:CICFLOW_CMD_TEMPLATE='"C:\path\to\cicflowmeter.exe" -f "{input}" -c "{output}"'
```

Important:

1. If teammate uses non-WSL command template, the placeholders `{input}` and `{output}` must be used.
2. If teammate uses WSL command template, placeholders `{input_wsl}` and `{output_dir_wsl}` must be used.
3. `EDITCAP_EXE` must also be valid for spool conversion step.

---


