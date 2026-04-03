# phishing_api.py
"""
Phishing Detection API - Automatic official domain detection
"""
import joblib

model = joblib.load('model.pkl')

import feature_extraction
import joblib
model = joblib.load('model.pkl')
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import joblib
import numpy as np
from datetime import datetime
import logging
import traceback
import re
from functools import wraps
from urllib.parse import urlparse
from feature_extraction import HTMLFeatureExtractor

# ---------------------------
# Configuration
# ---------------------------
app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rate limiting
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["100 per hour"])

# API keys
API_KEYS = {
    "test_key_123": "free",
    "premium_key_456": "premium"
}

# Feature extractor
extractor = HTMLFeatureExtractor()

# Load model
model = None
scaler = None
try:
    model = joblib.load("model.pkl")
    logger.info(f"✅ Model loaded - expects {model.n_features_in_} features")
except Exception as e:
    logger.error(f"❌ Model error: {e}")

try:
    scaler = joblib.load("scaler.pkl")
    logger.info(f"✅ Scaler loaded")
except Exception as e:
    logger.warning(f"⚠️ Scaler error: {e}")

# ---------------------------
# Domain checks
# ---------------------------
def is_official_domain(url):
    """Detect official or educational domains automatically"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        official_tlds = ['.gov', '.edu', '.mil', '.int']
        gov_patterns = [
            r'\.gov\.[a-z]{2}', r'\.govt\.[a-z]{2}', r'\.go\.kr',
            r'\.gouv\.[a-z]{2}', r'\.go\.jp', r'\.gov\.au', r'\.gc\.ca'
        ]
        edu_patterns = [
            r'\.edu\.[a-z]{2}', r'\.ac\.[a-z]{2}', r'\.sch\.[a-z]{2}',
            r'\.school\.[a-z]{2}', r'university\.', r'uni-', r'\.edu$'
        ]
        edu_keywords = ['university', 'college', 'institute', 'academy',
                        'education', 'school', 'campus', 'faculty']
        
        for tld in official_tlds:
            if domain.endswith(tld): return True
        for pattern in gov_patterns:
            if re.search(pattern, domain): return True
        for pattern in edu_patterns:
            if re.search(pattern, domain): return True
        for keyword in edu_keywords:
            if keyword in domain: return True
        
        return False
    except:
        return False

def is_trusted_website(url):
    """Detect globally trusted websites"""
    trusted = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
        'wikipedia.org', 'youtube.com', 'instagram.com'
    ]
    url_lower = url.lower()
    for site in trusted:
        if site in url_lower: return True
    return False

# ---------------------------
# Risk score calculation
# ---------------------------
def calculate_risk_score(features):
    risk_score = 0.0
    if features[13] == 1: risk_score += 0.4       # has IP
    if features[2] == 1: risk_score += 0.35       # has @
    if features[5] == 0: risk_score += 0.2        # no HTTPS
    if features[3] > 3: risk_score += 0.25        # sensitive words
    elif features[3] > 1: risk_score += 0.1
    if features[0] > 120: risk_score += 0.15      # long URL
    elif features[0] > 80: risk_score += 0.05
    if features[15] > 4: risk_score += 0.2        # many subdomains
    elif features[15] > 2: risk_score += 0.1
    if features[7] > 4: risk_score += 0.15        # many hyphens
    if features[17] > 3: risk_score += 0.1        # many question marks
    if features[18] > 5: risk_score += 0.1        # many equals
    if features[14] == 1: risk_score += 0.15      # unusual port
    return min(risk_score, 0.95)

# ---------------------------
# Authentication decorator
# ---------------------------
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key: return jsonify({'error': 'API key required'}), 401
        if api_key not in API_KEYS: return jsonify({'error': 'Invalid API key'}), 401
        request.api_key_type = API_KEYS[api_key]
        return f(*args, **kwargs)
    return decorated

# ---------------------------
# Routes
# ---------------------------
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'name': 'Phishing Detection API',
        'version': '2.0.0',
        'status': 'running',
        'features': {
            'auto_detect_official_domains': True,
            'rule_based_detection': True,
            'ml_model_available': model is not None
        }
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/v1/check', methods=['POST'])
@limiter.limit("100 per hour")
@require_api_key
def check_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing URL'}), 400
        url = data['url'].strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        if is_official_domain(url) or is_trusted_website(url):
            return jsonify({
                'status': 'success',
                'url': url,
                'is_phishing': False,
                'probability': 0.02,
                'risk_level': 'low',
                'confidence': 98.0,
                'detection_method': 'official_domain_whitelist',
                'message': '✅ Official or trusted website'
            }), 200
        
        features = extractor.extract_features_array(url)
        if features is None:
            return jsonify({'error': 'Feature extraction failed'}), 400
        
        risk_score = calculate_risk_score(features)
        prediction = 1 if risk_score > 0.5 else 0
        probability = risk_score
        risk_level = "low" if probability < 0.3 else "medium" if probability < 0.6 else "high"
        
        if model and prediction == 0:
            try:
                features_array = np.array(features).reshape(1, -1)
                if scaler and len(features) == scaler.mean_.shape[0]:
                    features_array = scaler.transform(features_array)
                ml_pred = model.predict(features_array)[0]
                ml_prob = model.predict_proba(features_array)[0][1]
                if ml_pred == 1 and ml_prob > 0.6:
                    probability = (probability + ml_prob) / 2
                    prediction = 1
                    risk_level = "medium" if probability < 0.6 else "high"
            except Exception as e:
                logger.warning(f"ML prediction failed: {e}")
        
        response = {
            'status': 'success',
            'url': url,
            'is_phishing': bool(prediction),
            'probability': float(probability),
            'risk_level': risk_level,
            'confidence': float((1 - abs(probability - 0.5) * 2) * 100),
            'timestamp': datetime.now().isoformat(),
            'detection_method': 'rule_based',
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
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

@app.route('/api/v1/batch', methods=['POST'])
@limiter.limit("50 per hour")
@require_api_key
def batch_check():
    try:
        data = request.get_json()
        if not data or 'urls' not in data: return jsonify({'error': 'Missing URLs'}), 400
        urls = data['urls'][:20]
        results = []
        for url in urls:
            url = url.strip()
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            if is_official_domain(url) or is_trusted_website(url):
                results.append({'url': url, 'is_phishing': False, 'probability': 0.02, 'risk_level': 'low'})
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
                results.append({'url': url, 'is_phishing': False, 'probability': 0.0, 'risk_level': 'unknown'})
        return jsonify({'status': 'success', 'total': len(results), 'results': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️ Phishing Detection API Server v2.0")
    print("="*60)
    print(f"📍 Model: {'✅' if model else '❌'}")
    print(f"📍 Official Domain Detection: ✅")
    print(f"📍 Rule-Based Detection: ✅")
    print(f"📍 Running on: http://localhost:5000")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
@app.route("/api/v1/check", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")

    # لازم تحول الرابط ل features
    features = feature_extraction(url)

    prediction = model.predict([features])

    return {
        "url": url,
        "is_phishing": bool(prediction[0])
    }