# ============================================================
#  PART 3 — detection.py
#  MODULE: Feature Extender + Anomaly Detection
#  WHAT IT DOES: Adds new features, runs ML model,
#                classifies each flow as SAFE or ATTACK
#  RUN IN COLAB: exec(open('detection.py').read())
# ============================================================

import pandas as pd
import numpy as np
import pickle
import random
import warnings
warnings.filterwarnings('ignore')

random.seed(42)

print("=" * 55)
print("  PART 3 — DETECTION MODULE (detection.py)")
print("=" * 55)
print("""
  WHAT THIS DOES:
  Module 2 — Feature Extender:
    Takes raw flow data and calculates 2 new features
    flow_intensity = pkt_count x pkt_rate
    burst_density  = pkt_count / duration²

  Module 3 — Anomaly Detection:
    Loads trained Random Forest model (rf_model.pkl)
    Classifies each flow as 0=SAFE or 1=ATTACK
    Gives a confidence % for each decision
""")

# ── Load model ────────────────────────────────────────────────
model    = pickle.load(open('rf_model.pkl','rb'))['model']
FEATURES = ['pkt_count','byte_count','duration_sec','pkt_rate',
            'byte_rate','byte_per_pkt','flow_intensity','burst_density']

print("  rf_model.pkl loaded successfully!")

# ── Feature Extender function ─────────────────────────────────
def extend_features(flows_df):
    """Module 2 — adds new detection criteria"""
    df = flows_df.copy()
    df['flow_intensity'] = df['pkt_count'] * df['pkt_rate']
    df['burst_density']  = df['pkt_count'] / (df['duration_sec'] ** 2)
    return df

# ── Detection function ────────────────────────────────────────
def detect_attacks(flows_df):
    """Module 3 — runs Random Forest on each flow"""
    df     = extend_features(flows_df)
    X      = df[FEATURES].values
    preds  = model.predict(X)
    probas = model.predict_proba(X)[:, 1]
    df['prediction']   = preds
    df['attack_prob']  = probas.round(3)
    return df

# ── Test on real dataset rows ─────────────────────────────────
print("\n  Testing on 10 real rows from FlowStatsfile_NEW.csv:")
df_data = pd.read_csv('FlowStatsfile_NEW.csv')
sample  = df_data.head(10).copy()
result  = detect_attacks(sample)

print(f"\n  {'Row':<5} {'pkt_rate':>9} {'byte/pkt':>9}"
      f" {'burst_den':>10} {'Real':>7} {'ML':>8} {'Conf':>7}")
print("  " + "-" * 58)

for i, row in result.iterrows():
    real = 'ATTACK' if row['label'] == 1 else 'SAFE'
    ml   = 'ATTACK' if row['prediction'] == 1 else 'SAFE'
    ok   = '✓' if real == ml else '✗'
    print(f"  {i+1:<5} {round(row['pkt_rate'],1):>9}"
          f" {round(row['byte_per_pkt']):>9}"
          f" {round(row['burst_density'],2):>10}"
          f" {real:>7} {ml:>7} {ok}"
          f" {round(row['attack_prob']*100,1):>5}%")

# ── Show detected attack flows ────────────────────────────────
attacks = result[result['prediction'] == 1]
print(f"\n  Attack flows detected : {len(attacks)} out of {len(result)}")
if len(attacks) > 0:
    print("  Attacker IPs found:")
    for ip in attacks['src_ip'].unique():
        a = attacks[attacks['src_ip']==ip].iloc[0]
        print(f"    {ip}  burst_density={round(a['burst_density'],2)}"
              f"  confidence={round(a['attack_prob']*100,1)}%")

print("\n  PART 3 DONE — Run Part 4 next (mitigation.py)")
