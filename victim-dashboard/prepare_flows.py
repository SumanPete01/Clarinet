import argparse
from pathlib import Path
import pandas as pd
import numpy as np


# ✅ YOUR EXACT FEATURE LIST
KEEP_COLUMNS = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min',
    'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
    'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Fwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
    'ECE Flag Count', 'Down/Up Ratio', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std',
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Std',
    'Idle Max', 'Idle Min'
]


import re
from difflib import get_close_matches

def prepare_flows_csv(input_path, output_path=None, expected_cols=None):
    df = pd.read_csv(input_path)
    if expected_cols is None:
        expected_cols = KEEP_COLUMNS

    KNOWN_MAPPINGS = {
        'total fwd packet': 'Total Fwd Packets',
        'total bwd packets': 'Total Backward Packets',
        'subflow fwd bytes': 'Total Length of Fwd Packets',
        'subflow bwd bytes': 'Total Length of Bwd Packets',
        'packet length min': 'Min Packet Length',
        'packet length max': 'Max Packet Length',
        'cwr flag count': 'CWE Flag Count',
        'fwd init win bytes': 'Init_Win_bytes_forward',
        'bwd init win bytes': 'Init_Win_bytes_backward',
        'fwd act data pkts': 'act_data_pkt_fwd',
        'fwd seg size min': 'min_seg_size_forward'
    }

    def normalize_col(c):
        return re.sub(r'[^a-zA-Z0-9]', '', str(c).lower().replace('fwd', 'forward').replace('bwd', 'backward'))

    input_norm = {normalize_col(c): c for c in df.columns}
    rename_mapping = {}

    input_lower = {str(c).strip().lower(): c for c in df.columns}
    for k, v in KNOWN_MAPPINGS.items():
        if k in input_lower:
            rename_mapping[input_lower[k]] = v

    for target in expected_cols:
        if target in rename_mapping.values():
            continue
        t_norm = normalize_col(target)
        if t_norm in input_norm:
            rename_mapping[input_norm[t_norm]] = target
        else:
            matches = get_close_matches(t_norm, list(input_norm.keys()), n=1, cutoff=0.7)
            if matches:
                rename_mapping[input_norm[matches[0]]] = target

    df.rename(columns=rename_mapping, inplace=True)
    
    for target in expected_cols:
        if target not in df.columns:
            print(f"Warning: adding missing column with 0s: {target}")
            df[target] = 0

    df = df[expected_cols]

    # optional cleanup (safe)
    df = df.apply(pd.to_numeric, errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(0)

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)

    return df


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-files", nargs="+", required=True)
    parser.add_argument("--output-dir", default="filtered_outputs")

    args = parser.parse_args()

    for file in args.input_files:
        output_file = Path(args.output_dir) / (Path(file).stem + "_filtered.csv")

        df = prepare_flows_csv(file, output_file)

        print(f"{file} -> {output_file} | shape={df.shape}")


if __name__ == "__main__":
    main()