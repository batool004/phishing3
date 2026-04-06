# 🛡️ PhishGuard - Phishing URL Detection System

An intelligent, real-time phishing URL detection system powered by Machine Learning, featuring a Flask API, Chrome Extension, and a modern web interface.

**[Live Demo Video URL]** *(اختياري، لكنه ممتاز للعرض)*

## ✨ Key Features

*   **Multi-Model Ensemble:** Combines Random Forest, XGBoost, and SVM for high accuracy (**~97.5%**).
*   **Real-time Protection:** Chrome extension scans links automatically while you browse.
*   **Typosquatting Detection:** Identifies deceptive domains like `faceb00k.com`.
*   **Modern GUI:** Cyberpunk-style interface with Matrix animation and Jordan flag.
*   **Collaborative Database:** Stores and shares threat intelligence via SQLite.
*   **Data Fusion:** Trained on **55,000+** URLs from PhishTank, LegitPhish, and custom datasets.

## 🛠️ Tech Stack

*   **Backend:** Python, Flask, Scikit-learn, XGBoost, Joblib
*   **Frontend:** HTML5, CSS3, JavaScript, TailwindCSS
*   **Extension:** Chrome Extension Manifest V3
*   **Database:** SQLite

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/batool004/phishing3.git
cd phishing3