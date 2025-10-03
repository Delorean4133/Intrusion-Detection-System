# realtime_score.py
import joblib
import pandas as pd
import time
import os
from featurize import extract_method, count_digits, count_special  # if we refactored; else duplicate small parsing
from datetime import datetime
import requests
import csv

MODEL_FILE = r"C:\Users\MSI PC\OneDrive\Documents\Network Security Case Study\iforest.joblib"
LOG_CSV = r"C:\Users\MSI PC\OneDrive\Documents\Network Security Case Study\logs.csv"
THRESHOLD = -0.5  # IsolationForest decision_function; adjust after calibration
PLAYBOOK_URL = "http://127.0.0.1:9001/alert"  # playbook webhook

model, columns = joblib.load(MODEL_FILE)

# helper to construct features for a single log row (must match featurize)
def make_features(row, ip_event_count=1):
    method = None
    import re
    m = re.search(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS)\b', str(row['raw']), re.I)
    method = (m.group(1).upper() if m else "OTHER")
    hour = pd.to_datetime(row['timestamp'], utc=True).hour
    msg_len = len(str(row['raw']))
    digits = sum(c.isdigit() for c in str(row['raw']))
    specials = sum(1 for c in str(row['raw']) if not c.isalnum() and not c.isspace())
    base = {
        'msg_len': msg_len, 'digits': digits, 'specials': specials,
        'hour': hour, 'ip_event_count': ip_event_count
    }
    # One-hot method fields
    rowvec = []
    for col in columns:
        if col in base:
            rowvec.append(base[col])
        elif col.startswith('m_'):
            rowvec.append(1 if col == f"m_{method}" else 0)
        else:
            rowvec.append(0)
    return rowvec

# simple tail - check file size and read new lines
def tail_csv(path, last_pos):
    with open(path, "r", newline='') as f:
        f.seek(last_pos)
        lines = f.readlines()
        newpos = f.tell()
    return lines, newpos

last_pos = 0
if os.path.exists(LOG_CSV):
    last_pos = os.path.getsize(LOG_CSV)

print("Starting realtime scorer watching", LOG_CSV)
while True:
    try:
        lines, last_pos = tail_csv(LOG_CSV, last_pos)
        for line in lines:
            # skip header
            if line.strip().startswith("timestamp") or not line.strip():
                continue
            ts, src_ip, raw = line.strip().split(",", 2)
            row = {'timestamp': ts, 'src_ip': src_ip, 'raw': raw}
            # naive ip_event_count = 1 for realtime; you can maintain sliding count
            vec = make_features(row, ip_event_count=1)
            import numpy as np
            score = model.decision_function([vec])[0]
            # lower score -> more anomalous for IsolationForest (negative)
            if score < THRESHOLD:
                print(f"[ALERT] {datetime.utcnow().isoformat()} {src_ip} score={score:.3f}")
                # send alert payload
                payload = {"timestamp": datetime.utcnow().isoformat(), "src_ip": src_ip, "raw": raw, "score": float(score)}
                try:
                    requests.post(PLAYBOOK_URL, json=payload, timeout=3)
                except Exception as e:
                    print("Failed to call playbook:", e)
        time.sleep(1)
    except KeyboardInterrupt:
        break
    except Exception as e:
        print("Error in tail loop:", e)
        time.sleep(2)
