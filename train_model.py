# train_model.py
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

FEAT_CSV = r"C:\Users\MSI PC\OneDrive\Documents\Network Security Case Study\features.csv"
MODEL_FILE = r"C:\Users\MSI PC\OneDrive\Documents\Network Security Case Study\iforest.joblib"

df = pd.read_csv(FEAT_CSV)
# drop NA
df = df.fillna(0)

model = IsolationForest(n_estimators=200, contamination=0.01, random_state=42)
model.fit(df.values)
joblib.dump((model, df.columns.tolist()), MODEL_FILE)
print("Trained IsolationForest and saved to", MODEL_FILE)
