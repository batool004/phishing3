# train_model.py - Training with 3 Models + Ensemble Learning

import pandas as pd
import numpy as np
import joblib
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import warnings
warnings.filterwarnings('ignore')

print("="*60)
print("🛡️ PHISHING URL DETECTION - 3 MODELS + ENSEMBLE")
print("="*60)

# ============= 1. LOAD DATASETS =============
print("\n📂 Loading datasets from data1 folder...")

all_urls = []
all_labels = []

# File 1: verified_online.csv (PhishTank)
try:
    df1 = pd.read_csv("data1/verified_online.csv")
    df1['is_phishing'] = (df1['target'] != 'Other').astype(int)
    all_urls.extend(df1['url'].tolist())
    all_labels.extend(df1['is_phishing'].tolist())
    print(f"   ✅ verified_online.csv: {len(df1)} URLs")
except Exception as e:
    print(f"   ⚠️ verified_online.csv not found: {e}")

# File 2: phishing_url_dataset.csv (Old)
try:
    df2 = pd.read_csv("data1/phishing_url_dataset.csv")
    all_urls.extend(df2['url'].tolist())
    all_labels.extend(df2['label'].tolist())
    print(f"   ✅ phishing_url_dataset.csv: {len(df2)} URLs")
except Exception as e:
    print(f"   ⚠️ phishing_url_dataset.csv not found: {e}")

# File 3: legitphish_dataset.csv (LegitPhish)
try:
    df3 = pd.read_csv("data1/legitphish_dataset.csv")
    # Convert: LegitPhish label (1=safe, 0=phishing) to our format (1=phishing, 0=safe)
    labels3 = [1 if x == 0 else 0 for x in df3['label'].tolist()]
    all_urls.extend(df3['url'].tolist())
    all_labels.extend(labels3)
    print(f"   ✅ legitphish_dataset.csv: {len(df3)} URLs")
except Exception as e:
    print(f"   ⚠️ legitphish_dataset.csv not found: {e}")

print(f"\n📊 TOTAL: {len(all_urls)} URLs")
print(f"   Phishing (1): {sum(all_labels)}")
print(f"   Safe (0): {len(all_labels) - sum(all_labels)}")

# ============= 2. EXTRACT FEATURES =============
print("\n🔧 Extracting features from URLs...")

def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_underscore'] = url.count('_')
    features['nb_slashes'] = url.count('/')
    features['nb_question'] = url.count('?')
    features['nb_equal'] = url.count('=')
    features['at_symbol'] = 1 if '@' in url else 0
    features['isHttps'] = 1 if url.startswith('https') else 0
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        features['domain_length'] = len(domain)
        features['nb_www'] = 1 if domain.startswith('www') else 0
        features['nb_com'] = 1 if domain.endswith('.com') else 0
    except:
        features['domain_length'] = 0
        features['nb_www'] = 0
        features['nb_com'] = 0
    
    suspicious = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'bank', 'paypal']
    url_lower = url.lower()
    features['sensitive_words_count'] = sum(1 for word in suspicious if word in url_lower)
    
    try:
        parsed = urlparse(url)
        features['path_length'] = len(parsed.path)
    except:
        features['path_length'] = 0
    
    features['valid_url'] = 1 if url.startswith('http') else 0
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.count('|')
    
    return features

features_list = []
total = len(all_urls)
for i, url in enumerate(all_urls):
    features_list.append(extract_features(url))
    if (i + 1) % 10000 == 0:
        print(f"   Processed {i+1}/{total} URLs...")

X = pd.DataFrame(features_list)
y = all_labels

print(f"\n✅ Extracted {len(X.columns)} features")
print(f"   Features: {X.columns.tolist()}")

# ============= 3. SPLIT DATA =============
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\n📊 Data split:")
print(f"   Training: {len(X_train)} samples")
print(f"   Testing: {len(X_test)} samples")

# ============= 4. TRAIN 3 MODELS SEPARATELY =============
print("\n" + "="*60)
print("🤖 TRAINING 3 MODELS SEPARATELY")
print("="*60)

# Model 1: Random Forest
print("\n🔄 Training Random Forest...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)
rf_accuracy = accuracy_score(y_test, rf_pred)
print(f"   ✅ Random Forest Accuracy: {rf_accuracy:.4f}")

# Model 2: XGBoost
print("\n🔄 Training XGBoost...")
xgb = XGBClassifier(n_estimators=100, random_state=42, use_label_encoder=False, eval_metric='logloss')
xgb.fit(X_train, y_train)
xgb_pred = xgb.predict(X_test)
xgb_accuracy = accuracy_score(y_test, xgb_pred)
print(f"   ✅ XGBoost Accuracy: {xgb_accuracy:.4f}")

# Model 3: SVM
print("\n🔄 Training SVM...")
svm = SVC(kernel='rbf', probability=True, random_state=42)
svm.fit(X_train, y_train)
svm_pred = svm.predict(X_test)
svm_accuracy = accuracy_score(y_test, svm_pred)
print(f"   ✅ SVM Accuracy: {svm_accuracy:.4f}")

# ============= 5. ENSEMBLE LEARNING (Voting) =============
print("\n" + "="*60)
print("🤝 ENSEMBLE LEARNING (Voting Classifier)")
print("="*60)

ensemble = VotingClassifier(
    estimators=[
        ('rf', rf),
        ('xgb', xgb),
        ('svm', svm)
    ],
    voting='soft'  # 'soft' uses predicted probabilities
)

ensemble.fit(X_train, y_train)
ensemble_pred = ensemble.predict(X_test)
ensemble_accuracy = accuracy_score(y_test, ensemble_pred)
ensemble_precision = precision_score(y_test, ensemble_pred)
ensemble_recall = recall_score(y_test, ensemble_pred)
ensemble_f1 = f1_score(y_test, ensemble_pred)

print(f"\n📊 ENSEMBLE RESULTS:")
print(f"   Accuracy:  {ensemble_accuracy:.4f}")
print(f"   Precision: {ensemble_precision:.4f}")
print(f"   Recall:    {ensemble_recall:.4f}")
print(f"   F1-Score:  {ensemble_f1:.4f}")

# ============= 6. COMPARISON TABLE =============
print("\n" + "="*60)
print("📊 MODEL COMPARISON")
print("="*60)

comparison_data = {
    'Model': ['Random Forest', 'XGBoost', 'SVM', 'Ensemble (Voting)'],
    'Accuracy': [rf_accuracy, xgb_accuracy, svm_accuracy, ensemble_accuracy],
    'Precision': [
        precision_score(y_test, rf_pred),
        precision_score(y_test, xgb_pred),
        precision_score(y_test, svm_pred),
        ensemble_precision
    ],
    'Recall': [
        recall_score(y_test, rf_pred),
        recall_score(y_test, xgb_pred),
        recall_score(y_test, svm_pred),
        ensemble_recall
    ],
    'F1-Score': [
        f1_score(y_test, rf_pred),
        f1_score(y_test, xgb_pred),
        f1_score(y_test, svm_pred),
        ensemble_f1
    ]
}

comparison_df = pd.DataFrame(comparison_data)
print(comparison_df.to_string(index=False))

# Save comparison
comparison_df.to_csv('model_comparison.csv', index=False)
print("\n✅ Model comparison saved to 'model_comparison.csv'")

# ============= 7. SAVE BEST MODEL (Ensemble) =============
print("\n💾 Saving Ensemble model...")
joblib.dump(ensemble, 'model.pkl')
joblib.dump(X.columns.tolist(), 'feature_columns.pkl')
print("✅ Model saved to 'model.pkl'")
print("✅ Feature columns saved to 'feature_columns.pkl'")

# ============= 8. SUMMARY =============
print("\n" + "="*60)
print("🏆 BEST MODEL: Ensemble (Voting Classifier)")
print("="*60)
print(f"""
   Random Forest:  {rf_accuracy:.4f}
   XGBoost:        {xgb_accuracy:.4f}
   SVM:            {svm_accuracy:.4f}
   ───────────────────────────
   ✅ ENSEMBLE:     {ensemble_accuracy:.4f}
""")

print("\n✅ TRAINING COMPLETE!")
print("="*60)

# ============= 9. VISUALIZATION - Model Comparison Chart =============
print("\n" + "="*60)
print("📊 GENERATING MODEL COMPARISON CHART")
print("="*60)

import matplotlib.pyplot as plt

# Data for comparison
models = ['Random Forest', 'XGBoost', 'SVM', 'Ensemble']
accuracy = [rf_accuracy, xgb_accuracy, svm_accuracy, ensemble_accuracy]
precision = [
    precision_score(y_test, rf_pred),
    precision_score(y_test, xgb_pred),
    precision_score(y_test, svm_pred),
    ensemble_precision
]
recall = [
    recall_score(y_test, rf_pred),
    recall_score(y_test, xgb_pred),
    recall_score(y_test, svm_pred),
    ensemble_recall
]
f1 = [
    f1_score(y_test, rf_pred),
    f1_score(y_test, xgb_pred),
    f1_score(y_test, svm_pred),
    ensemble_f1
]

# Create figure with 2 subplots
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

# Bar chart 1: Accuracy comparison
x_pos = range(len(models))
bars1 = ax1.bar(x_pos, accuracy, color=['#667eea', '#764ba2', '#f093fb', '#4facfe'])
ax1.set_xticks(x_pos)
ax1.set_xticklabels(models, rotation=15, ha='right')
ax1.set_ylabel('Accuracy', fontsize=12, fontweight='bold')
ax1.set_title('Model Accuracy Comparison', fontsize=14, fontweight='bold')
ax1.set_ylim(0.94, 0.98)

# Add value labels on bars
for bar, val in zip(bars1, accuracy):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001,
             f'{val:.4f}', ha='center', va='bottom', fontsize=10, fontweight='bold')

# Highlight Ensemble bar
bars1[3].set_color('#4facfe')
bars1[3].set_edgecolor('darkblue')
bars1[3].set_linewidth(2)

# Bar chart 2: Precision, Recall, F1-Score comparison
x_pos = range(len(models))
width = 0.25

bars2_prec = ax2.bar([p - width for p in x_pos], precision, width, label='Precision', color='#667eea')
bars2_rec = ax2.bar(x_pos, recall, width, label='Recall', color='#764ba2')
bars2_f1 = ax2.bar([p + width for p in x_pos], f1, width, label='F1-Score', color='#4facfe')

ax2.set_xticks(x_pos)
ax2.set_xticklabels(models, rotation=15, ha='right')
ax2.set_ylabel('Score', fontsize=12, fontweight='bold')
ax2.set_title('Precision, Recall & F1-Score Comparison', fontsize=14, fontweight='bold')
ax2.set_ylim(0.94, 0.98)
ax2.legend(loc='lower right')

# Add value labels
for bar in bars2_prec:
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001,
             f'{bar.get_height():.4f}', ha='center', va='bottom', fontsize=8)
for bar in bars2_rec:
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001,
             f'{bar.get_height():.4f}', ha='center', va='bottom', fontsize=8)
for bar in bars2_f1:
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001,
             f'{bar.get_height():.4f}', ha='center', va='bottom', fontsize=8)

plt.tight_layout()
plt.savefig('model_comparison_chart.png', dpi=300, bbox_inches='tight')
plt.show()

print("✅ Model comparison chart saved as 'model_comparison_chart.png'")