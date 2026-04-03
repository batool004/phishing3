import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score, 
                             confusion_matrix, classification_report, roc_auc_score, 
                             roc_curve, precision_recall_curve)
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

# ----------------------------
# Add Feature Extraction for direct URL input
# ----------------------------
from feature_extraction import HTMLFeatureExtractor  # <-- إضافة جديدة

# ----------------------------
# Configuration
# ----------------------------
RANDOM_STATE = 42
TEST_SIZE = 0.2
CV_FOLDS = 5

# ----------------------------
# 1️⃣ Load and Explore Data (CSV)
# ----------------------------
print("="*60)
print("🛡️ PHISHING URL DETECTION SYSTEM - MODEL TRAINING")
print("="*60)

# Load dataset
print("\n📂 Loading dataset...")
df = pd.read_csv("data3/phishing_url_dataset.csv")

# Display basic information
print(f"\n✅ Dataset loaded successfully!")
print(f"📊 Dataset shape: {df.shape}")
print(f"📋 Columns: {list(df.columns)}")
print(f"\n📈 Basic statistics:")
print(df.describe())

# Check for missing values
print(f"\n🔍 Missing values:")
print(df.isnull().sum())

# Check class distribution
print(f"\n🎯 Class distribution:")
target_counts = df['target'].value_counts()
print(target_counts)
print(f"\nClass balance: {target_counts[0]/len(df):.2%} safe, {target_counts[1]/len(df):.2%} phishing")

# ----------------------------
# 2️⃣ Feature Engineering
# ----------------------------
print("\n" + "="*60)
print("🔧 FEATURE ENGINEERING")
print("="*60)

# Define feature columns
base_features = [
    "url_length", "valid_url", "at_symbol", "sensitive_words_count",
    "path_length", "isHttps", "nb_dots", "nb_hyphens",
    "nb_and", "nb_or", "nb_www", "nb_com", "nb_underscore"
]

# Add interaction and ratio features
df['dots_per_length'] = df['nb_dots'] / (df['url_length'] + 1)
df['hyphens_per_length'] = df['nb_hyphens'] / (df['url_length'] + 1)
df['security_score'] = df['isHttps'] * 2 - (df['at_symbol'] + df['nb_underscore'])
df['complexity_score'] = df['nb_dots'] + df['nb_hyphens'] + df['nb_underscore']
df['special_chars_ratio'] = (df['nb_dots'] + df['nb_hyphens'] + df['nb_underscore']) / (df['url_length'] + 1)
df['has_www_and_com'] = ((df['nb_www'] > 0) & (df['nb_com'] > 0)).astype(int)
df['sensitive_words'] = df['sensitive_words_count'].apply(lambda x: 1 if x > 0 else 0)

# Final feature list
feature_columns = base_features + [
    'dots_per_length', 'hyphens_per_length', 'security_score', 
    'complexity_score', 'special_chars_ratio', 'has_www_and_com', 'sensitive_words'
]

X = df[feature_columns]
y = df["target"]

print(f"\n✅ Feature engineering complete!")
print(f"📊 Total features: {len(feature_columns)}")
print(f"📋 Features: {feature_columns}")

# ----------------------------
# 3️⃣ Handle Class Imbalance
# ----------------------------
print("\n" + "="*60)
print("⚖️ HANDLING CLASS IMBALANCE")
print("="*60)

if target_counts[0] / target_counts[1] < 0.8 or target_counts[1] / target_counts[0] < 0.8:
    print("\n⚠️ Class imbalance detected! Applying SMOTE...")
    smote = SMOTE(random_state=RANDOM_STATE)
    X_resampled, y_resampled = smote.fit_resample(X, y)
    print(f"✅ After SMOTE - New class distribution: {pd.Series(y_resampled).value_counts().values}")
    X_train, X_test, y_train, y_test = train_test_split(
        X_resampled, y_resampled, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_resampled
    )
else:
    print("\n✅ Balanced dataset detected!")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

print(f"\n📊 Train set size: {X_train.shape}")
print(f"📊 Test set size: {X_test.shape}")

# ----------------------------
# 4️⃣ Feature Scaling
# ----------------------------
print("\n" + "="*60)
print("📐 FEATURE SCALING")
print("="*60)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("✅ Features scaled successfully!")

# ----------------------------
# 5️⃣ Model Training & Comparison
# ----------------------------
print("\n" + "="*60)
print("🤖 MODEL TRAINING & COMPARISON")
print("="*60)

models = {
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE),
    'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=RANDOM_STATE),
    'Logistic Regression': LogisticRegression(random_state=RANDOM_STATE, max_iter=1000),
    'SVM': SVC(probability=True, random_state=RANDOM_STATE)
}

results = {}

for name, model in models.items():
    print(f"🔄 Training {name}...")
    model.fit(X_train_scaled, y_train)
    
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)[:, 1] if hasattr(model, 'predict_proba') else None
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=CV_FOLDS, scoring='accuracy')
    roc_auc = roc_auc_score(y_test, y_pred_proba) if y_pred_proba is not None else None
    
    results[name] = {
        'Accuracy': accuracy,
        'Precision': precision,
        'Recall': recall,
        'F1-Score': f1,
        'CV Mean': cv_scores.mean(),
        'CV Std': cv_scores.std(),
        'ROC-AUC': roc_auc,
        'Model': model,
        'Predictions': y_pred,
        'Probabilities': y_pred_proba
    }
    
    print(f"  ✅ Accuracy: {accuracy:.4f}")
    print(f"  ✅ F1-Score: {f1:.4f}")
    print(f"  ✅ CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    if roc_auc:
        print(f"  ✅ ROC-AUC: {roc_auc:.4f}")
    print()

# ----------------------------
# 6️⃣ Best Model Selection & Hyperparameter Tuning
# ----------------------------
print("\n" + "="*60)
print("🏆 BEST MODEL SELECTION & TUNING")
print("="*60)

best_model_name = max(results, key=lambda x: results[x]['F1-Score'])
best_model = results[best_model_name]['Model']
print(f"\n🎯 Best model based on F1-Score: {best_model_name}")

if best_model_name == 'Random Forest':
    print("\n🔧 Performing hyperparameter tuning...")
    param_grid = {
        'n_estimators': [100, 200, 300],
        'max_depth': [10, 20, 30, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
        'max_features': ['sqrt', 'log2']
    }
    grid_search = GridSearchCV(
        RandomForestClassifier(random_state=RANDOM_STATE),
        param_grid,
        cv=CV_FOLDS,
        scoring='f1',
        n_jobs=-1,
        verbose=1
    )
    grid_search.fit(X_train_scaled, y_train)
    best_model = grid_search.best_estimator_
    print(f"\n✅ Best parameters: {grid_search.best_params_}")
    print(f"✅ Best CV F1-Score: {grid_search.best_score_:.4f}")

final_model = best_model.fit(X_train_scaled, y_train)

# ----------------------------
# 7️⃣ Final Evaluation
# ----------------------------
print("\n" + "="*60)
print("📈 FINAL MODEL EVALUATION")
print("="*60)

y_pred_final = final_model.predict(X_test_scaled)
y_pred_proba_final = final_model.predict_proba(X_test_scaled)[:, 1]

final_accuracy = accuracy_score(y_test, y_pred_final)
final_precision = precision_score(y_test, y_pred_final)
final_recall = recall_score(y_test, y_pred_final)
final_f1 = f1_score(y_test, y_pred_final)
final_roc_auc = roc_auc_score(y_test, y_pred_proba_final)

print(f"\n🎯 Final Model Performance:")
print(f"  ✅ Accuracy:  {final_accuracy:.4f}")
print(f"  ✅ Precision: {final_precision:.4f}")
print(f"  ✅ Recall:    {final_recall:.4f}")
print(f"  ✅ F1-Score:  {final_f1:.4f}")
print(f"  ✅ ROC-AUC:   {final_roc_auc:.4f}")

print(f"\n📋 Classification Report:")
print(classification_report(y_test, y_pred_final, target_names=['Safe', 'Phishing']))

# ----------------------------
# 8️⃣ Confusion Matrix & Plots
# ----------------------------
print("\n" + "="*60)
print("🎨 VISUALIZATIONS")
print("="*60)

fig, axes = plt.subplots(2, 2, figsize=(15, 12))
cm = confusion_matrix(y_test, y_pred_final)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0, 0])
axes[0, 0].set_title('Confusion Matrix', fontsize=14, fontweight='bold')
axes[0, 0].set_xlabel('Predicted'); axes[0, 0].set_ylabel('Actual')
axes[0, 0].set_xticklabels(['Safe', 'Phishing']); axes[0, 0].set_yticklabels(['Safe', 'Phishing'])

fpr, tpr, _ = roc_curve(y_test, y_pred_proba_final)
axes[0, 1].plot(fpr, tpr, 'b-', linewidth=2, label=f'ROC Curve (AUC = {final_roc_auc:.3f})')
axes[0, 1].plot([0,1],[0,1],'r--', linewidth=1, label='Random Classifier')
axes[0, 1].set_xlabel('False Positive Rate'); axes[0, 1].set_ylabel('True Positive Rate')
axes[0, 1].set_title('ROC Curve', fontsize=14, fontweight='bold'); axes[0, 1].legend(); axes[0,1].grid(True, alpha=0.3)

precision_curve, recall_curve, _ = precision_recall_curve(y_test, y_pred_proba_final)
axes[1, 0].plot(recall_curve, precision_curve, 'g-', linewidth=2)
axes[1, 0].set_xlabel('Recall'); axes[1,0].set_ylabel('Precision')
axes[1,0].set_title('Precision-Recall Curve', fontsize=14, fontweight='bold'); axes[1,0].grid(True, alpha=0.3)

if hasattr(final_model, 'feature_importances_'):
    importances = final_model.feature_importances_
    indices = np.argsort(importances)[::-1][:15]
    axes[1,1].barh(range(len(indices)), importances[indices], align='center')
    axes[1,1].set_yticks(range(len(indices))); axes[1,1].set_yticklabels([feature_columns[i] for i in indices])
    axes[1,1].set_xlabel('Feature Importance'); axes[1,1].set_title('Top 15 Feature Importances', fontsize=14, fontweight='bold')
    axes[1,1].invert_yaxis()

plt.tight_layout(); plt.savefig('model_evaluation.png', dpi=300, bbox_inches='tight'); plt.show()
print("\n✅ Visualization saved as 'model_evaluation.png'")

# ----------------------------
# 9️⃣ Save Model and Artifacts
# ----------------------------
print("\n" + "="*60)
print("💾 SAVING MODEL AND ARTIFACTS")
print("="*60)

joblib.dump(final_model, "model.pkl"); print("✅ Model saved as 'model.pkl'")
joblib.dump(scaler, "scaler.pkl"); print("✅ Scaler saved as 'scaler.pkl'")
joblib.dump(feature_columns, "feature_columns.pkl"); print("✅ Feature columns saved as 'feature_columns.pkl'")

model_info = {
    'model_type': best_model_name,
    'accuracy': final_accuracy,
    'precision': final_precision,
    'recall': final_recall,
    'f1_score': final_f1,
    'roc_auc': final_roc_auc,
    'feature_columns': feature_columns,
    'n_features': len(feature_columns),
    'train_size': len(X_train),
    'test_size': len(X_test)
}
joblib.dump(model_info, "model_info.pkl"); print("✅ Model info saved as 'model_info.pkl'")

results_df = pd.DataFrame({
    'Model': list(results.keys()),
    'Accuracy': [results[m]['Accuracy'] for m in results],
    'Precision': [results[m]['Precision'] for m in results],
    'Recall': [results[m]['Recall'] for m in results],
    'F1-Score': [results[m]['F1-Score'] for m in results],
    'CV Mean': [results[m]['CV Mean'] for m in results],
    'CV Std': [results[m]['CV Std'] for m in results],
    'ROC-AUC': [results[m]['ROC-AUC'] for m in results]
})
results_df.to_csv('model_comparison.csv', index=False)
print("✅ Model comparison saved as 'model_comparison.csv'")

# ----------------------------
# 🔟 Training Summary
# ----------------------------
print("\n" + "="*60)
print("📊 TRAINING SUMMARY REPORT")
print("="*60)

print(f"""
╔══════════════════════════════════════════════════════════╗
║              MODEL TRAINING COMPLETE!                    ║
╠══════════════════════════════════════════════════════════╣
║  Best Model:        {best_model_name:<35}║
║  Accuracy:          {final_accuracy:.4f} ({final_accuracy*100:.2f}%){' ' * 30}║
║  Precision:         {final_precision:.4f} ({final_precision*100:.2f}%){' ' * 30}║
║  Recall:            {final_recall:.4f} ({final_recall*100:.2f}%){' ' * 30}║
║  F1-Score:          {final_f1:.4f} ({final_f1*100:.2f}%){' ' * 30}║
║  ROC-AUC:           {final_roc_auc:.4f} ({final_roc_auc*100:.2f}%){' ' * 30}║
╠══════════════════════════════════════════════════════════╣
║  Dataset Size:      {len(df):<35}║
║  Features Used:     {len(feature_columns):<35}║
║  Train/Test Split:  {TEST_SIZE*100:.0f}% test{' ' * 35}║
║  Cross-Validation:  {CV_FOLDS}-fold{' ' * 40}║
╠══════════════════════════════════════════════════════════╣
║  Files Saved:                                            ║
║  • model.pkl (trained model)                             ║
║  • scaler.pkl (feature scaler)                           ║
║  • feature_columns.pkl (feature list)                    ║
║  • model_info.pkl (performance metrics)                  ║
║  • model_comparison.csv (all models comparison)          ║
║  • model_evaluation.png (visualizations)                 ║
╚══════════════════════════════════════════════════════════╝
""")

print("\n🎉 Training completed successfully!")

# ----------------------------
# 1️⃣1️⃣ Optional: Using HTMLFeatureExtractor for new URL
# ----------------------------
# Uncomment below to extract features from a new URL directly:
# extractor = HTMLFeatureExtractor()
# new_url = "https://example.com"
# new_features = extractor.extract_features(new_url)
# X_new = pd.DataFrame([new_features])
# X_new_scaled = scaler.transform(X_new)
# prediction = final_model.predict(X_new_scaled)
# print(f"Prediction for {new_url}: {prediction[0]}")