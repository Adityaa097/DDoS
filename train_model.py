# ============================================================
#  PART 2 — train_model.py
#  MODULE: Train ML Models
#  WHAT IT DOES: Reads dataset, trains 4 ML models,
#                saves best model as rf_model.pkl
#  RUN IN COLAB: exec(open('train_model.py').read())
# ============================================================

import pandas as pd
import numpy as np
import pickle
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split
from sklearn.ensemble        import (RandomForestClassifier,
                                      GradientBoostingClassifier)
from sklearn.svm             import SVC
from sklearn.neighbors       import KNeighborsClassifier
from sklearn.preprocessing   import StandardScaler
from sklearn.metrics         import (accuracy_score, precision_score,
                                      recall_score, f1_score,
                                      confusion_matrix)

print("=" * 55)
print("  PART 2 — TRAIN ML MODELS (train_model.py)")
print("=" * 55)
print("""
  WHAT THIS DOES:
  Reads FlowStatsfile_NEW.csv (2000 rows of network data)
  Adds 2 NEW detection criteria from the data
  Trains 4 ML models to detect safe vs attack traffic
  Saves the best model as rf_model.pkl

  NEW CRITERIA 1: flow_intensity = pkt_count x pkt_rate
  NEW CRITERIA 2: burst_density  = pkt_count / duration²
""")

# ── Load dataset ─────────────────────────────────────────────
df = pd.read_csv('FlowStatsfile_NEW.csv')

# Add new criteria
df['flow_intensity'] = df['pkt_count'] * df['pkt_rate']
df['burst_density']  = df['pkt_count'] / (df['duration_sec'] ** 2)

print(f"  Dataset loaded: {len(df)} rows")
print(f"  Safe rows  (0): {(df['label']==0).sum()}")
print(f"  Attack rows(1): {(df['label']==1).sum()}")

# ── Show new criteria power ───────────────────────────────────
print("\n  NEW CRITERIA — how they detect attacks:")
for feat in ['flow_intensity', 'burst_density']:
    n = df[df['label']==0][feat].mean()
    a = df[df['label']==1][feat].mean()
    print(f"    {feat}")
    print(f"      Safe avg   = {n:,.2f}")
    print(f"      Attack avg = {a:,.2f}")
    print(f"      Attack is {a/n:.0f}x HIGHER than safe!")

# ── Features ─────────────────────────────────────────────────
FEATURES = [
    'pkt_count', 'byte_count', 'duration_sec',
    'pkt_rate',  'byte_rate',  'byte_per_pkt',
    'flow_intensity',   # NEW CRITERIA 1
    'burst_density',    # NEW CRITERIA 2
]

X = df[FEATURES].values
y = df['label'].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y)

scaler  = StandardScaler()
Xtr_sc  = scaler.fit_transform(X_train)
Xte_sc  = scaler.transform(X_test)

# ── Train 4 models ────────────────────────────────────────────
models = {
    'Random Forest'    : (RandomForestClassifier(
                           n_estimators=100, random_state=42),
                          X_train, X_test),
    'SVM'              : (SVC(kernel='rbf', probability=True,
                           random_state=42), Xtr_sc, Xte_sc),
    'KNN (k=5)'        : (KNeighborsClassifier(n_neighbors=5),
                          Xtr_sc, Xte_sc),
    'Gradient Boosting': (GradientBoostingClassifier(
                           n_estimators=100, random_state=42),
                          X_train, X_test),
}

print(f"\n  Training on {len(X_train)} rows, testing on {len(X_test)} rows\n")
print(f"  {'Model':<22} {'Accuracy':>9} {'Precision':>10}"
      f" {'Recall':>8} {'F1':>8}")
print("  " + "-" * 60)

best_clf = None
best_acc = 0
results  = {}

for name, (clf, Xtr, Xte) in models.items():
    clf.fit(Xtr, y_train)
    y_pred = clf.predict(Xte)
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    results[name] = dict(clf=clf, pred=y_pred)
    new = "  ← NEW MODEL" if name == "Gradient Boosting" else ""
    win = "  ← WINNER"   if acc > best_acc else ""
    print(f"  {name:<22} {acc*100:>8.2f}%"
          f" {prec*100:>9.2f}% {rec*100:>7.2f}%"
          f" {f1*100:>7.2f}%{new}{win}")
    if acc > best_acc:
        best_acc = acc
        best_clf = clf

print("  " + "-" * 60)

# ── Confusion matrix ──────────────────────────────────────────
cm = confusion_matrix(y_test, results['Random Forest']['pred'])
print(f"\n  CONFUSION MATRIX (Random Forest):")
print(f"                  Predicted SAFE  Predicted ATTACK")
print(f"  Actual SAFE          {cm[0,0]:>5}             {cm[0,1]:>5}")
print(f"  Actual ATTACK        {cm[1,0]:>5}             {cm[1,1]:>5}")
print(f"\n  TP={cm[1,1]}  TN={cm[0,0]}  FP={cm[0,1]}  FN={cm[1,0]}"
      f"  →  {'PERFECT!' if cm[0,1]==0 and cm[1,0]==0 else 'Has errors'}")

# ── Feature importance ────────────────────────────────────────
print(f"\n  FEATURE IMPORTANCE (Random Forest):")
rf  = results['Random Forest']['clf']
imp = sorted(zip(FEATURES, rf.feature_importances_), key=lambda x:-x[1])
for feat, score in imp:
    bar = '█' * int(score * 35)
    new = "  ← NEW" if feat in ('flow_intensity','burst_density') else ""
    print(f"    {feat:<18}  {score:.3f}  {bar}{new}")

# ── Save model ────────────────────────────────────────────────
pickle.dump({'model': best_clf, 'features': FEATURES},
            open('rf_model.pkl', 'wb'))
print(f"\n  rf_model.pkl SAVED! Best model ready to use.")
print("\n  PART 2 DONE — Run Part 3 next (detection.py)")
