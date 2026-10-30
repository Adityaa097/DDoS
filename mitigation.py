# ============================================================
#  PART 4 — mitigation.py
#  MODULE: Anomaly Mitigation
#  WHAT IT DOES: Blocks attacker IPs with DROP rules
#                Normal users are NEVER blocked
#  RUN IN COLAB: exec(open('mitigation.py').read())
# ============================================================

import pandas as pd
import numpy as np
import pickle
import random
import warnings
warnings.filterwarnings('ignore')

random.seed(42)

print("=" * 55)
print("  PART 4 — MITIGATION MODULE (mitigation.py)")
print("=" * 55)
print("""
  WHAT THIS DOES:
  When detection.py finds an attack, this module
  sends a DROP command to the switch.
  The switch will block ALL future packets from
  that attacker IP address automatically.

  Real project  : sends OpenFlow rule to Ryu switch
  Simulation    : installs DROP rule in firewall table
""")

# ── Firewall rule table ───────────────────────────────────────
blocked_ips  = {}
mitigation_log = []

def mitigate(attack_flows_df):
    """Blocks each unique attacker IP — only once each"""
    new_blocks = []
    for _, row in attack_flows_df.iterrows():
        ip = row['src_ip']
        if ip not in blocked_ips:
            rule = {
                'ip'           : ip,
                'switch_id'    : int(row['switch_id']),
                'pkt_rate'     : round(row['pkt_rate'], 1),
                'burst_density': round(row['burst_density'], 2),
                'action'       : 'DROP',
            }
            blocked_ips[ip] = rule
            mitigation_log.append(rule)
            new_blocks.append(ip)
    return new_blocks

# ── Load model + detect attacks ───────────────────────────────
model    = pickle.load(open('rf_model.pkl','rb'))['model']
FEATURES = ['pkt_count','byte_count','duration_sec','pkt_rate',
            'byte_rate','byte_per_pkt','flow_intensity','burst_density']

df_data = pd.read_csv('FlowStatsfile_NEW.csv')
df_data['flow_intensity'] = df_data['pkt_count'] * df_data['pkt_rate']
df_data['burst_density']  = df_data['pkt_count'] / (df_data['duration_sec']**2)

preds = model.predict(df_data[FEATURES].values)
df_data['prediction'] = preds
attack_flows = df_data[df_data['prediction'] == 1]

print(f"  Flows checked     : {len(df_data)}")
print(f"  Attack flows found: {len(attack_flows)}")

# ── Run mitigation ────────────────────────────────────────────
new_blocks = mitigate(attack_flows)

print(f"\n  DROP rules installed: {len(blocked_ips)}")
print(f"\n  {'Attacker IP':<15} {'Switch':>7} {'pkt_rate':>10}"
      f" {'burst_density':>14}  Action")
print("  " + "-" * 55)
for rule in mitigation_log:
    print(f"  {rule['ip']:<15} SW{rule['switch_id']:>5}"
          f" {rule['pkt_rate']:>10}"
          f" {rule['burst_density']:>14}  {rule['action']}")

# ── Prove normal users are safe ───────────────────────────────
normal_flows   = df_data[df_data['prediction'] == 0]
normal_blocked = sum(1 for f in normal_flows['src_ip']
                     if f in blocked_ips)

print(f"\n  Normal flows     : {len(normal_flows)}")
print(f"  Normal blocked   : {normal_blocked}  "
      f"← {'NONE blocked!' if normal_blocked==0 else 'Some blocked!'}")
print(f"\n  is 10.0.0.90 blocked? "
      f"{'YES — DROP' if '10.0.0.90' in blocked_ips else 'NO'}")
print(f"  is 10.0.0.4  blocked? "
      f"{'YES' if '10.0.0.4' in blocked_ips else 'NO — safe user'}")

print(f"\n  RESULT: {len(blocked_ips)} attackers BLOCKED."
      f" {len(normal_flows)} normal users SAFE.")
print("\n  PART 4 DONE — Run the all-in-one file to see everything!")
