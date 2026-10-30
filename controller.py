# ============================================================
#  PART 1 — controller.py
#  MODULE: Flow Collector
#  WHAT IT DOES: Collects network traffic from all switches
#                every 5 seconds like a security camera
#  RUN IN COLAB: exec(open('controller.py').read())
# ============================================================

import pandas as pd
import numpy as np
import random
import warnings
warnings.filterwarnings('ignore')

random.seed(42)
np.random.seed(42)

SWITCHES     = [1, 2, 3, 4]
ATTACKER_IPS = ['10.0.0.90', '10.0.0.91', '10.0.0.92']
NORMAL_IPS   = [f'10.0.0.{i}' for i in range(2, 20)]
VICTIM_IP    = '10.0.0.1'

print("=" * 55)
print("  PART 1 — FLOW COLLECTOR (controller.py)")
print("=" * 55)
print("""
  WHAT THIS DOES:
  Every 5 seconds the Ryu SDN Controller contacts
  all switches and collects a list of all flows.
  A flow = one network conversation between 2 computers.

  In real project : talks to actual Ryu controller
  In simulation   : we generate realistic fake flows
""")

def collect_flows(attack_active=False, round_num=1):
    """Simulates Ryu REST API polling all 4 switches"""
    flows = []
    for sw in SWITCHES:
        # Normal flows from real users
        for _ in range(random.randint(8, 14)):
            d = random.uniform(15, 200)
            p = random.randint(30, 400)
            b = p * random.randint(400, 1400)
            flows.append({
                'round'       : round_num,
                'switch_id'   : sw,
                'src_ip'      : random.choice(NORMAL_IPS),
                'dst_ip'      : random.choice(NORMAL_IPS),
                'pkt_count'   : p,
                'byte_count'  : b,
                'duration_sec': round(d, 2),
                'pkt_rate'    : round(p / d, 4),
                'byte_rate'   : round(b / d, 4),
                'byte_per_pkt': round(b / p, 4),
                'is_attack'   : 0
            })
        # Attack flows (only when attack is active)
        if attack_active:
            for ip in ATTACKER_IPS:
                d = random.uniform(0.5, 4)
                p = random.randint(800, 4500)
                b = p * random.randint(40, 80)
                flows.append({
                    'round'       : round_num,
                    'switch_id'   : sw,
                    'src_ip'      : ip,
                    'dst_ip'      : VICTIM_IP,
                    'pkt_count'   : p,
                    'byte_count'  : b,
                    'duration_sec': round(d, 2),
                    'pkt_rate'    : round(p / d, 4),
                    'byte_rate'   : round(b / d, 4),
                    'byte_per_pkt': round(b / p, 4),
                    'is_attack'   : 1
                })
    random.shuffle(flows)
    return flows

# Demonstrate flow collection for 3 rounds
print("  Collecting flows from 4 switches...\n")
print(f"  {'Round':<6} {'Status':<22} {'Flows Collected'}")
print("  " + "-" * 42)

all_collected = []
for rnd in range(1, 4):
    atk   = (rnd == 3)   # attack starts at round 3
    flows = collect_flows(attack_active=atk, round_num=rnd)
    all_collected.extend(flows)
    status = "⚠  ATTACK ACTIVE" if atk else "✓  Normal traffic"
    print(f"  {rnd:<6} {status:<22} {len(flows)} flows")

df_collected = pd.DataFrame(all_collected)

print(f"\n  Total flows collected : {len(df_collected)}")
print(f"  Normal flows          : {(df_collected['is_attack']==0).sum()}")
print(f"  Attack flows          : {(df_collected['is_attack']==1).sum()}")

print("\n  Sample NORMAL flow collected:")
r = df_collected[df_collected['is_attack']==0].iloc[0]
print(f"    src={r['src_ip']}  pkt_rate={round(r['pkt_rate'],1)}"
      f"  byte/pkt={round(r['byte_per_pkt'])}  switch={r['switch_id']}")

print("\n  Sample ATTACK flow collected:")
r = df_collected[df_collected['is_attack']==1].iloc[0]
print(f"    src={r['src_ip']}  pkt_rate={round(r['pkt_rate'],1)}"
      f"  byte/pkt={round(r['byte_per_pkt'])}  switch={r['switch_id']}")

# Save collected flows for next module
df_collected.to_csv('collected_flows.csv', index=False)
print(f"\n  Flows saved to collected_flows.csv")
print("\n  PART 1 DONE — Run Part 2 next (train_model.py)")
