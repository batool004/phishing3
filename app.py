# phishing_app.py
"""
Phishing Detection - Flask Server with HTML Interface
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import joblib
import numpy as np
from datetime import datetime
import logging
import re
from urllib.parse import urlparse
from feature_extraction import HTMLFeatureExtractor

app = Flask(__name__)
CORS(app)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Feature extractor
extractor = HTMLFeatureExtractor()

# Load ML model
model = None
scaler = None
try:
    model = joblib.load("model.pkl")
    logger.info("✅ Model loaded")
except:
    logger.error("❌ Model not found")

try:
    scaler = joblib.load("scaler.pkl")
    logger.info("✅ Scaler loaded")
except:
    pass

# -------------------------------
# Official domain check
# -------------------------------
def is_official_domain(url):
    """Detect official domains"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        official_tlds = ['.gov', '.edu', '.mil', '.int']
        for tld in official_tlds:
            if domain.endswith(tld):
                return True, f"Official domain ({tld})"
        
        gov_patterns = [r'\.gov\.[a-z]{2}', r'\.govt\.[a-z]{2}', r'\.go\.[a-z]{2}']
        for pattern in gov_patterns:
            if re.search(pattern, domain):
                return True, "Government domain"
        
        edu_patterns = [r'\.edu\.[a-z]{2}', r'\.ac\.[a-z]{2}', r'\.sch\.[a-z]{2}']
        for pattern in edu_patterns:
            if re.search(pattern, domain):
                return True, "Educational domain"
        
        edu_keywords = ['university', 'college', 'institute', 'school', 'education']
        for keyword in edu_keywords:
            if keyword in domain:
                return True, "Educational institution"
        
        return False, None
    except Exception:
        return False, None

def is_trusted_website(url):
    """Check if website is globally trusted"""
    trusted = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
        'wikipedia.org', 'youtube.com', 'instagram.com'
    ]
    url_lower = url.lower()
    for site in trusted:
        if site in url_lower:
            return True
    return False

# -------------------------------
# Risk score calculation
# -------------------------------
def calculate_risk_score(features):
    if features is None:
        return 0.5
    risk_score = 0.0
    if features[13] == 1:
        risk_score += 0.4
    if features[2] == 1:
        risk_score += 0.35
    if features[5] == 0:
        risk_score += 0.2
    if features[3] > 3:
        risk_score += 0.25
    elif features[3] > 1:
        risk_score += 0.1
    if features[0] > 120:
        risk_score += 0.15
    if features[15] > 4:
        risk_score += 0.2
    return min(risk_score, 0.95)

# -------------------------------
# Routes
# -------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/v1/check', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing URL'}), 400
        
        url = data['url'].strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        is_official, reason = is_official_domain(url)
        if is_official:
            return jsonify({
                'status': 'success',
                'url': url,
                'is_phishing': False,
                'probability': 0.02,
                'risk_level': 'low',
                'confidence': 98.0,
                'detection_method': 'official_domain',
                'message': f'✅ Official / trusted website - {reason}',
                'timestamp': datetime.now().isoformat()
            })
        
        if is_trusted_website(url):
            return jsonify({
                'status': 'success',
                'url': url,
                'is_phishing': False,
                'probability': 0.03,
                'risk_level': 'low',
                'confidence': 97.0,
                'detection_method': 'trusted',
                'message': '✅ Trusted global website',
                'timestamp': datetime.now().isoformat()
            })
        
        features = extractor.extract_features_array(url)
        if features is None:
            return jsonify({'error': 'Feature extraction failed'}), 400
        
        risk_score = calculate_risk_score(features)
        prediction = risk_score > 0.5
        probability = risk_score

        if model:
            try:
                features_array = np.array(features).reshape(1, -1)
                if scaler and len(features) == scaler.mean_.shape[0]:
                    features_array = scaler.transform(features_array)
                ml_pred = model.predict(features_array)[0]
                ml_prob = model.predict_proba(features_array)[0][1]
                if ml_pred == 1 and ml_prob > 0.6:
                    probability = (probability + ml_prob) / 2
                    prediction = True
            except:
                pass

        if probability < 0.3:
            risk_level = "low"
        elif probability < 0.6:
            risk_level = "medium"
        else:
            risk_level = "high"

        response = {
            'status': 'success',
            'url': url,
            'is_phishing': bool(prediction),
            'probability': float(probability),
            'risk_level': risk_level,
            'confidence': float((1 - abs(probability - 0.5) * 2) * 100),
            'timestamp': datetime.now().isoformat(),
            'detection_method': 'ml' if model else 'rule_based',
            'features_summary': {
                'url_length': features[0],
                'has_https': bool(features[5]),
                'sensitive_words': features[3],
                'has_ip': bool(features[13]),
                'num_subdomains': features[15]
            }
        }
        return jsonify(response), 200
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/batch', methods=['POST'])
def batch_check():
    try:
        data = request.get_json()
        if not data or 'urls' not in data:
            return jsonify({'error': 'Missing URLs'}), 400
        
        urls = data['urls'][:20]
        results = []
        for url in urls:
            url = url.strip()
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            is_official, _ = is_official_domain(url)
            if is_official or is_trusted_website(url):
                results.append({
                    'url': url,
                    'is_phishing': False,
                    'probability': 0.02,
                    'risk_level': 'low'
                })
                continue
            features = extractor.extract_features_array(url)
            if features:
                risk_score = calculate_risk_score(features)
                results.append({
                    'url': url,
                    'is_phishing': risk_score > 0.5,
                    'probability': risk_score,
                    'risk_level': 'low' if risk_score < 0.3 else 'medium' if risk_score < 0.6 else 'high'
                })
            else:
                results.append({
                    'url': url,
                    'is_phishing': False,
                    'probability': 0.0,
                    'risk_level': 'unknown'
                })
        return jsonify({'status': 'success', 'total': len(results), 'results': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️ Phishing Detection System - Web Interface")
    print("="*60)
    print(f"📍 Model: {'✅' if model else '❌'}")
    print(f"📍 Web Interface: http://localhost:5000")
    print(f"📍 API: http://localhost:5000/api/v1/check")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)