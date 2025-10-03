# featurize.py
# Reads logs.csv and produces features.csv
import pandas as pd
import re
from dateutil import parser
from collections import Counter
import numpy as np

IN_CSV = r"C:\Users\MSI PC\OneDrive\Documents\Network Security Case Study\logs.csv"
OUT_FEAT = r"C:\Users\MSI PC\OneDrive\Documents\Network Security Case Study\features.csv"

df = pd.read_csv(IN_CSV)
# Basic parsing
def extract_method(text):
    # naive example: look for GET/POST/PUT/DELETE or SQL keywords
    m = re.search(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS)\b', str(text), re.I)
    return (m.group(1).upper() if m else "OTHER")

def count_digits(s): return sum(c.isdigit() for c in str(s))
def count_special(s): return sum(1 for c in str(s) if not c.isalnum() and not c.isspace())

df['ts'] = pd.to_datetime(df['timestamp'], utc=True)
df['hour'] = df['ts'].dt.hour
df['msg_len'] = df['raw'].str.len()
df['digits'] = df['raw'].apply(count_digits)
df['specials'] = df['raw'].apply(count_special)
df['method'] = df['raw'].apply(extract_method)

# count recent events from same src_ip (simple rolling count)
ip_counts = df['src_ip'].value_counts().to_dict()
df['ip_event_count'] = df['src_ip'].map(ip_counts).fillna(0)

# one-hot encode method
one_hot = pd.get_dummies(df['method'], prefix='m')
feats = pd.concat([df[['msg_len','digits','specials','hour','ip_event_count']], one_hot], axis=1)

# optional normalization
feats = (feats - feats.mean()) / (feats.std().replace(0,1))

feats.to_csv(OUT_FEAT, index=False)
print("Wrote", OUT_FEAT)
