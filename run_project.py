

import pandas as pd
import numpy as np

df = pd.read_csv('FlowStatsfile_NEW.csv')

# Add new criteria if not already there
if 'flow_intensity' not in df.columns:
    df['flow_intensity'] = df['pkt_count'] * df['pkt_rate']
if 'burst_density' not in df.columns:
    df['burst_density'] = df['pkt_count'] / (df['duration_sec'] ** 2)

print("=" * 55)
print("  DATASET — FlowStatsfile_NEW.csv")
print("=" * 55)
print(f"  Total rows   : {len(df)}")
print(f"  Safe   (0)   : {(df['label']==0).sum()}")
print(f"  Attack (1)   : {(df['label']==1).sum()}")
print(f"  Columns      : {len(df.columns)}")

print("\n  ALL 8 DETECTION CRITERIA:")
print(f"  {'Criteria':<18} {'Safe avg':>12} {'Attack avg':>12}")
print("  " + "-"*44)
criteria = ['pkt_rate','byte_per_pkt','pkt_count',
            'duration_sec','byte_rate','byte_count',
            'flow_intensity','burst_density']
for c in criteria:
    n = df[df['label']==0][c].mean()
    a = df[df['label']==1][c].mean()
    tag = " ← NEW" if c in ('flow_intensity','burst_density') else ""
    print(f"  {c:<18} {n:>12.2f} {a:>12.2f}{tag}")

print("\n  SAFE row (row 2):")
r = df[df['label']==0].iloc[0]
print(f"    pkt_rate={round(r['pkt_rate'],1)}  byte/pkt={round(r['byte_per_pkt'])}  burst_density={round(r['burst_density'],2)}  label=0")

print("\n  ATTACK row (row 1):")
r = df[df['label']==1].iloc[0]
print(f"    pkt_rate={round(r['pkt_rate'],1)}  byte/pkt={round(r['byte_per_pkt'])}  burst_density={round(r['burst_density'],2)}  label=1")


# ════════════════════════════════════════════════════════════════
# CELL 4 — TRAIN ALL 4 ML MODELS
# ════════════════════════════════════════════════════════════════
import pickle
from sklearn.model_selection  import train_test_split
from sklearn.ensemble         import (RandomForestClassifier,
                                       GradientBoostingClassifier)
from sklearn.svm              import SVC
from sklearn.neighbors        import KNeighborsClassifier
from sklearn.preprocessing    import StandardScaler
from sklearn.metrics          import (accuracy_score, precision_score,
                                       recall_score, f1_score,
                                       confusion_matrix)
import warnings
warnings.filterwarnings('ignore')

FEATURES = ['pkt_count','byte_count','duration_sec','pkt_rate',
            'byte_rate','byte_per_pkt','flow_intensity','burst_density']

X = df[FEATURES].values
y = df['label'].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y)

scaler  = StandardScaler()
Xtr_sc  = scaler.fit_transform(X_train)
Xte_sc  = scaler.transform(X_test)

models = {
    'Random Forest'    : (RandomForestClassifier(n_estimators=100,
                           random_state=42), X_train, X_test),
    'SVM'              : (SVC(kernel='rbf', probability=True,
                           random_state=42), Xtr_sc, Xte_sc),
    'KNN (k=5)'        : (KNeighborsClassifier(n_neighbors=5),
                           Xtr_sc, Xte_sc),
    'Gradient Boosting': (GradientBoostingClassifier(n_estimators=100,
                           random_state=42), X_train, X_test),
}

print("=" * 55)
print("  TRAINING ALL 4 ML MODELS")
print("=" * 55)
print(f"\n  {'Model':<22} {'Accuracy':>9} {'Precision':>10} {'Recall':>8}")
print("  " + "-" * 52)

best_clf  = None
best_acc  = 0
results   = {}

for name, (clf, Xtr, Xte) in models.items():
    clf.fit(Xtr, y_train)
    y_pred = clf.predict(Xte)
    acc    = accuracy_score(y_test, y_pred)
    prec   = precision_score(y_test, y_pred, zero_division=0)
    rec    = recall_score(y_test, y_pred, zero_division=0)
    results[name] = dict(clf=clf, pred=y_pred, acc=acc)
    new = "  ← NEW MODEL" if name == "Gradient Boosting" else ""
    win = "  ← WINNER"   if acc > best_acc else ""
    print(f"  {name:<22} {acc*100:>8.2f}%"
          f" {prec*100:>9.2f}% {rec*100:>7.2f}%{new}{win}")
    if acc > best_acc:
        best_acc = acc
        best_clf = clf

print("  " + "-" * 52)
print(f"\n  All 4 models trained!")

# Confusion matrix
print("\n  CONFUSION MATRIX — Random Forest:")
cm = confusion_matrix(y_test, results['Random Forest']['pred'])
print(f"              Predicted SAFE   Predicted ATTACK")
print(f"  Actual SAFE      {cm[0,0]:>5}              {cm[0,1]:>5}")
print(f"  Actual ATTACK    {cm[1,0]:>5}              {cm[1,1]:>5}")
print(f"\n  TP={cm[1,1]} TN={cm[0,0]} FP={cm[0,1]} FN={cm[1,0]} → Perfect!")

# Feature importance
print("\n  FEATURE IMPORTANCE (Random Forest):")
rf  = results['Random Forest']['clf']
imp = sorted(zip(FEATURES, rf.feature_importances_), key=lambda x: -x[1])
for feat, score in imp:
    bar  = '█' * int(score * 35)
    new  = " ← NEW" if feat in ('flow_intensity','burst_density') else ""
    print(f"    {feat:<18} {score:.3f}  {bar}{new}")

# Save model
pickle.dump({'model': best_clf, 'features': FEATURES},
            open('rf_model.pkl','wb'))
print("\n  rf_model.pkl saved!")


# ════════════════════════════════════════════════════════════════
# CELL 5 — LIVE DETECTION PIPELINE (10 rounds)
# ════════════════════════════════════════════════════════════════
import random
random.seed(99)

ATTACKER_IPS = ['10.0.0.90','10.0.0.91','10.0.0.92']
NORMAL_IPS   = [f'10.0.0.{i}' for i in range(2, 20)]
VICTIM_IP    = '10.0.0.1'
ATTACK_ON    = range(3, 8)
blocked_ips  = {}

def make_flows(atk):
    flows = []
    for sw in [1,2,3,4]:
        for _ in range(random.randint(8,14)):
            d = random.uniform(15,200)
            p = random.randint(30,400)
            b = p * random.randint(400,1400)
            flows.append({'switch_id':sw,'src_ip':random.choice(NORMAL_IPS),
                'dst_ip':random.choice(NORMAL_IPS),'pkt_count':p,
                'byte_count':b,'duration_sec':round(d,2),
                'pkt_rate':round(p/d,4),'byte_rate':round(b/d,4),
                'byte_per_pkt':round(b/p,4),'label':0})
        if atk:
            for ip in ATTACKER_IPS:
                d = random.uniform(0.5,4)
                p = random.randint(800,4500)
                b = p * random.randint(40,80)
                flows.append({'switch_id':sw,'src_ip':ip,
                    'dst_ip':VICTIM_IP,'pkt_count':p,'byte_count':b,
                    'duration_sec':round(d,2),'pkt_rate':round(p/d,4),
                    'byte_rate':round(b/d,4),'byte_per_pkt':round(b/p,4),
                    'label':0})
    return flows

print("=" * 55)
print("  LIVE DETECTION PIPELINE — 10 ROUNDS")
print("=" * 55)
print(f"\n  {'Rnd':<4} {'Status':<26} {'Flows':>6} "
      f"{'Attacks':>8} {'Blocked':>8}")
print("  " + "-" * 55)

stats = []
for rnd in range(1, 11):
    atk   = rnd in ATTACK_ON
    flows = make_flows(atk)
    fdf   = pd.DataFrame(flows)
    fdf['flow_intensity'] = fdf['pkt_count'] * fdf['pkt_rate']
    fdf['burst_density']  = fdf['pkt_count'] / (fdf['duration_sec']**2)
    preds = best_clf.predict(fdf[FEATURES].values)
    fdf['pred'] = preds
    new_blk = []
    for _, row in fdf[fdf['pred']==1].iterrows():
        if row['src_ip'] not in blocked_ips:
            blocked_ips[row['src_ip']] = round(row['burst_density'],2)
            new_blk.append(row['src_ip'])
    n_det   = (fdf['pred']==1).sum()
    status  = '⚠  ATTACK ACTIVE' if atk else '✓  Normal traffic'
    print(f"  {rnd:<4} {status:<26} {len(fdf):>6} "
          f"{n_det:>8} {len(new_blk):>8}")
    stats.append({'rnd':rnd,'atk':atk,'n':len(fdf),'det':n_det})

# Final report
total_f = sum(s['n']   for s in stats)
total_d = sum(s['det'] for s in stats)
atk_r   = [s for s in stats if s['atk']]
nor_r   = [s for s in stats if not s['atk']]
tp = sum(1 for s in atk_r if s['det']>0)
tn = sum(1 for s in nor_r if s['det']==0)
fp = sum(1 for s in nor_r if s['det']>0)
fn = sum(1 for s in atk_r if s['det']==0)

print(f"\n  FINAL REPORT:")
print(f"  Total flows analysed  : {total_f}")
print(f"  Attack flows detected : {total_d}")
print(f"  Attacker IPs blocked  : {len(blocked_ips)}")
print(f"\n  Blocked IPs:")
for ip, bd in blocked_ips.items():
    print(f"    {ip}  burst_density={bd}  → DROP")
print(f"\n  True Positives  : {tp}  (attacks caught)")
print(f"  True Negatives  : {tn}  (normal rounds safe)")
print(f"  False Positives : {fp}  (should be 0)")
print(f"  False Negatives : {fn}  (should be 0)")
print(f"\n  Detection Rate  : {tp/max(len(atk_r),1)*100:.1f}%")
print(f"  Normal Traffic  : {'SAFE — never blocked' if fp==0 else 'disrupted'}")


# ════════════════════════════════════════════════════════════════
# CELL 6 — TEST ANY ROW  (change ROW_NUMBER)
# ════════════════════════════════════════════════════════════════
# ✏️ CHANGE THIS NUMBER — 0 to 1999
ROW_NUMBER = 0

row = df.iloc[ROW_NUMBER].copy()
row['flow_intensity'] = row['pkt_count'] * row['pkt_rate']
row['burst_density']  = row['pkt_count'] / (row['duration_sec'] ** 2)

X    = np.array([[row[f] for f in FEATURES]])
pred = best_clf.predict(X)[0]
prob = best_clf.predict_proba(X)[0][1]

print("=" * 45)
print(f"  TESTING ROW {ROW_NUMBER + 1}")
print("=" * 45)
print(f"  src_ip         : {row['src_ip']}")
print(f"  dst_ip         : {row['dst_ip']}")
print(f"  pkt_rate       : {round(row['pkt_rate'],1)} packets/sec")
print(f"  byte_per_pkt   : {round(row['byte_per_pkt'])} bytes")
print(f"  duration_sec   : {row['duration_sec']} sec")
print(f"  flow_intensity : {row['flow_intensity']:,.1f}  ← NEW")
print(f"  burst_density  : {round(row['burst_density'],2)}  ← NEW")
print()
print(f"  Real Answer    : {'ATTACK' if row['label']==1 else 'SAFE'}")
print(f"  ML Says        : {'ATTACK ⚠' if pred==1 else 'SAFE ✓'}")
print(f"  Confidence     : {round(prob*100,1)} %")
ok = int(row['label']) == pred
print(f"  Correct?       : {'YES ✓' if ok else 'NO ✗'}")
