# NetSentry AI — ML Model Training & Artifact Specification

**Target Audience:** ML Teammate (Model Training & Artifact Delivery)  
**Author:** Backend Team (Saurav)  
**Contract Version:** `v1.0`  
**Target Artifact Path:** `ml/models/isolation_forest_v1.joblib`  

---

## 1. Executive Summary & Delivery Scope

The backend pipeline, feature extraction, database storage, LangGraph investigation agent, and Streamlit SOC dashboard are **100% complete and operational**.

To transition from the heuristic baseline (`v0-stub`) to production ML (`v1.0`), your single deliverable is:
> A serialized joblib artifact at **`ml/models/isolation_forest_v1.joblib`** packaged as a **dictionary** containing the trained model, fitted scaler, feature ordering, and version tag.

The backend loads this model in-process at startup. As long as you respect the **12-feature ordering contract**, your model will seamlessly plug into the live API without any backend code changes.

---

## 2. Frozen Contract: 12-Feature Specification

Your model and scaler **must** consume feature vectors in this exact sequence (defined in `features/schema.json`):

| Index | Feature Name | Description | Source in CIC-IDS2017 |
|:---:|:---|:---|:---|
| 0 | `duration` | Flow duration in seconds | `Flow Duration` (microseconds / 1e6) |
| 1 | `orig_bytes` | Payload/header bytes sent from source | `Total Length of Fwd Packets` |
| 2 | `resp_bytes` | Payload/header bytes sent from destination | `Total Length of Bwd Packets` |
| 3 | `total_bytes` | Sum of forward and backward bytes | `orig_bytes + resp_bytes` |
| 4 | `orig_pkts` | Total packet count from source | `Total Fwd Packets` |
| 5 | `resp_pkts` | Total packet count from destination | `Total Backward Packets` |
| 6 | `bytes_per_sec` | Total bytes divided by duration | `Flow Bytes/s` or `total_bytes / max(duration, 0.001)` |
| 7 | `pkts_per_sec` | Total packets divided by duration | `Flow Packets/s` or `(orig_pkts + resp_pkts) / max(duration, 0.001)` |
| 8 | `dst_port` | Destination port number | `Destination Port` |
| 9 | `protocol_TCP` | 1 if TCP, 0 otherwise | `1` if `Protocol == 6` else `0` |
| 10 | `unique_dst_ports_5min` | Unique destination ports by source in 5m window | Derived rolling window (or default `1`) |
| 11 | `failed_conn_ratio_5min` | Fraction of failed/unanswered connections in 5m | Derived rolling window (or default `0.0`) |

---

## 3. Dataset Strategy: CIC-IDS2017

Use the **CIC-IDS2017** benchmark (Canadian Institute for Cybersecurity).

### Data Split for Training & Validation
1. **Training Baseline (100% Benign)**:
   - Use **`Monday-WorkingHours.pcap_ISCX.csv`**.
   - Contains ~529,000 pure benign enterprise flows.
   - *Rationale:* Isolation Forest is an unsupervised detector that learns the boundary of normal network behavior. Training on uncontaminated benign data ensures clean separation of novel bursts and scans.
2. **Validation & Threshold Calibration (Benign + Attacks)**:
   - Held-out 20% of `Monday-WorkingHours.pcap_ISCX.csv` (Benign evaluation).
   - Subset of **`Friday-WorkingHours-PortScan.pcap_ISCX.csv`** (Evaluates `unique_dst_ports_5min` & scan detection).
   - Subset of **`Wednesday-WorkingHours.pcap_ISCX.csv`** (Evaluates DoS/DDoS burst volume detection).

---

## 4. Feature Engineering Logic

### Features 0 to 9 (Per-Flow Calculation)
```python
import numpy as np
import pandas as pd

def extract_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    # Clean duration (convert from microseconds to seconds)
    duration = np.maximum(df['Flow Duration'].astype(float) / 1e6, 0.001)
    orig_bytes = df['Total Length of Fwd Packets'].astype(int)
    resp_bytes = df['Total Length of Bwd Packets'].astype(int)
    total_bytes = orig_bytes + resp_bytes
    orig_pkts = df['Total Fwd Packets'].astype(int)
    resp_pkts = df['Total Backward Packets'].astype(int)
    total_pkts = orig_pkts + resp_pkts

    df_out = pd.DataFrame()
    df_out['duration'] = duration
    df_out['orig_bytes'] = orig_bytes
    df_out['resp_bytes'] = resp_bytes
    df_out['total_bytes'] = total_bytes
    df_out['orig_pkts'] = orig_pkts
    df_out['resp_pkts'] = resp_pkts
    df_out['bytes_per_sec'] = total_bytes / duration
    df_out['pkts_per_sec'] = total_pkts / duration
    df_out['dst_port'] = df['Destination Port'].astype(int)
    df_out['protocol_TCP'] = (df['Protocol'] == 6).astype(int)
    return df_out
```

### Features 10 & 11 (5-Minute Rolling Windows)
If your raw CSV includes `Source IP` and `Timestamp`:
```python
def add_rolling_features(df: pd.DataFrame) -> pd.DataFrame:
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df = df.sort_values('Timestamp')

    # A connection is considered failed if the server never responded (0 return packets)
    df['is_failed'] = (df['Total Backward Packets'] == 0).astype(int)
    df = df.set_index('Timestamp')

    # Rolling 5m unique destination ports
    df['unique_dst_ports_5min'] = (
        df.groupby('Source IP')['Destination Port']
          .rolling('5min')
          .apply(lambda s: len(set(s)), raw=False)
          .reset_index(level=0, drop=True)
    )

    # Rolling 5m failed connection ratio
    failed_5m = df.groupby('Source IP')['is_failed'].rolling('5min').sum().reset_index(level=0, drop=True)
    total_5m = df.groupby('Source IP')['is_failed'].rolling('5min').count().reset_index(level=0, drop=True)
    df['failed_conn_ratio_5min'] = (failed_5m / total_5m).fillna(0.0)

    return df.reset_index()
```
*Note for pre-cleaned CSVs lacking IPs/Timestamps:*  
Benign enterprise traffic rarely scans or fails. You can default `unique_dst_ports_5min = 1` and `failed_conn_ratio_5min = 0.0` for benign rows, and assign synthetic port-scan distributions ($\ge 10$ unique ports, $\ge 0.5$ failed ratio) to attack rows.

---

## 5. End-to-End Training & Serialization Script

Save and run this script to generate the required artifact:

```python
"""train_isolation_forest.py — NetSentry ML Model Trainer."""
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_ORDER = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "total_bytes",
    "orig_pkts",
    "resp_pkts",
    "bytes_per_sec",
    "pkts_per_sec",
    "dst_port",
    "protocol_TCP",
    "unique_dst_ports_5min",
    "failed_conn_ratio_5min"
]

def main():
    print("[1/5] Loading benign training data (Monday-WorkingHours)...")
    # Replace with your local path to Monday-WorkingHours.pcap_ISCX.csv
    df_raw = pd.read_csv("data/Monday-WorkingHours.pcap_ISCX.csv")
    df_raw.columns = df_raw.columns.str.strip()

    print("[2/5] Extracting 12 contract features...")
    # Clean infinities and nulls common in network captures
    df_raw.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_raw.dropna(subset=['Flow Duration', 'Total Length of Fwd Packets'], inplace=True)

    # Compute features
    duration = np.maximum(df_raw['Flow Duration'].astype(float) / 1e6, 0.001)
    orig_bytes = df_raw['Total Length of Fwd Packets'].astype(int)
    resp_bytes = df_raw['Total Length of Bwd Packets'].astype(int)
    total_bytes = orig_bytes + resp_bytes
    orig_pkts = df_raw['Total Fwd Packets'].astype(int)
    resp_pkts = df_raw['Total Backward Packets'].astype(int)

    X = pd.DataFrame()
    X['duration'] = duration
    X['orig_bytes'] = orig_bytes
    X['resp_bytes'] = resp_bytes
    X['total_bytes'] = total_bytes
    X['orig_pkts'] = orig_pkts
    X['resp_pkts'] = resp_pkts
    X['bytes_per_sec'] = total_bytes / duration
    X['pkts_per_sec'] = (orig_pkts + resp_pkts) / duration
    X['dst_port'] = df_raw['Destination Port'].astype(int)
    X['protocol_TCP'] = (df_raw.get('Protocol', 6) == 6).astype(int)
    X['unique_dst_ports_5min'] = 1
    X['failed_conn_ratio_5min'] = 0.0

    # Ensure clean numeric matrix
    X = X[FEATURE_ORDER].fillna(0.0)

    print(f"[3/5] Fitting StandardScaler on {len(X)} benign flows...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("[4/5] Training IsolationForest baseline...")
    model = IsolationForest(
        n_estimators=150,
        max_samples=256,
        contamination=0.01,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    # Sanity check score calibration:
    # NetSentry maps normalized score = max(0.0, min(1.0, 0.5 - decision_function))
    raw_dec = model.decision_function(X_scaled[:5])
    norm_scores = np.clip(0.5 - raw_dec, 0.0, 1.0)
    print(f"Sample benign normalized scores (should be < 0.60): {np.round(norm_scores, 3)}")

    print("[5/5] Packaging artifact dictionary...")
    artifact = {
        "model": model,
        "scaler": scaler,
        "feature_order": FEATURE_ORDER,
        "version": "v1.0"
    }

    out_dir = "ml/models"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "isolation_forest_v1.joblib")
    joblib.dump(artifact, out_path)
    print(f"Successfully saved artifact to: {out_path}")

if __name__ == "__main__":
    main()
```

---

## 6. How the Backend Scores Your Model

In `ml/real.py`, the backend normalizes your model's output using:
$$\text{anomaly\_score} = \text{clamp}(0.5 - \text{decision\_function}(\text{vector}),\ 0.0,\ 1.0)$$

The backend uses `configs/threshold.yaml` to classify incidents:
- **$\text{Score} < 0.60$**: Normal traffic (stored for analytics, no event).
- **$0.60 \le \text{Score} < 0.85$**: Monitoring event created in dashboard.
- **$\text{Score} \ge 0.85$**: High anomaly (triggers LangGraph agentic investigation & incident report).

*Guideline:* Validate that normal traffic stays below $0.60$, while deliberate attack bursts/port-scans score $\ge 0.85$.

---

## 7. Verification & Handoff Checklist

Before handing the `.joblib` file back to the backend team:

- [ ] Artifact is saved at `ml/models/isolation_forest_v1.joblib`.
- [ ] Artifact is a dictionary containing keys: `"model"`, `"scaler"`, `"feature_order"`, and `"version"`.
- [ ] Feature order matches `features/schema.json` exactly (12 features).
- [ ] Run the local validator (must output `ok: True`):
  ```bash
  python -c "from ml.validate import validate_artifact; print(validate_artifact('ml/models/isolation_forest_v1.joblib'))"
  ```
- [ ] Test the backend live validation endpoint (without server restart):
  ```bash
  curl -X POST http://localhost:8000/model/validate
  ```
- [ ] Run test suite to verify no regressions:
  ```bash
  pytest tests/ -q
  ```
- [ ] Provide test metrics (Precision, Recall, F1, ROC-AUC, and False Positive Rate) for inclusion in the project report.
