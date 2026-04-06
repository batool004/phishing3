# smart_api.py - Intelligent API with background page analysis

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import joblib
import numpy as np
import time
import threading
from intelligent_analyzer import analyzer
from deep_page_analyzer import deep_analyzer
from threat_db import threat_db
from feature_extraction import HTMLFeatureExtractor

app = Flask(__name__)
CORS(app)

# Load the main model
print("📦 Loading models...")
model = joblib.load('model.pkl')
feature_columns = joblib.load('feature_columns.pkl')
print("✅ Models ready!")

# Cache for deep scan results
deep_scan_cache = {}

@app.route('/smart-check', methods=['POST'])
def smart_check():
    """Smart check with advanced analysis"""
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'Please enter a URL'}), 400
    
    start_time = time.time()
    
    # 1. Quick analysis (URL only)
    quick_result = analyzer.analyze_url(url)
    
    # 2. Check threat database
    threat_check = threat_db.check_threat(url)
    
    # 3. If URL is suspicious, open page in background
    deep_result = None
    if quick_result['needs_deep_scan'] and url not in deep_scan_cache:
        # Open page in separate thread (doesn't slow response)
        def background_scan():
            deep_scan_cache[url] = deep_analyzer.analyze_in_background(url)
        
        thread = threading.Thread(target=background_scan)
        thread.start()
        
        # Wait a bit (0.5 seconds) for quick result
        thread.join(timeout=0.5)
        
        deep_result = deep_scan_cache.get(url)
    
    # 4. Merge results
    final_score = quick_result['score']
    final_risks = quick_result['risk_factors'].copy()
    
    if deep_result and deep_result.get('page_loaded'):
        # Add risks from page analysis
        final_score = max(final_score, deep_result['overall_score'])
        final_risks.extend(deep_result['suspicious_texts'][:3])
        
        if deep_result['has_login_form']:
            final_risks.append('⚠️ Page contains a login form requesting password')
        
        if deep_result['has_credit_card_form']:
            final_risks.append('⚠️ Page requests credit card information!')
    
    # 5. Determine final result
    if final_score > 70 or (threat_check and threat_check.get('is_threat')):
        prediction = 'phishing'
        final_recommendation = '🚫 Do not open this URL under any circumstances'
        icon = '⚠️🚫'
    elif final_score > 40:
        prediction = 'suspicious'
        final_recommendation = '⚠️ Exercise extreme caution'
        icon = '⚠️'
    else:
        prediction = 'safe'
        final_recommendation = '✅ URL appears safe'
        icon = '✅'
    
    analysis_time = round(time.time() - start_time, 2)
    
    # 6. Save result to database
    threat_db.add_scan(url, prediction, final_score)
    
    # 7. Response
    return jsonify({
        'url': url,
        'prediction': prediction,
        'is_phishing': prediction == 'phishing',
        'score': final_score,
        'confidence': final_score,
        'explanation': quick_result['summary'],
        'recommendation': final_recommendation,
        'risk_factors': final_risks[:8],
        'deep_analysis_performed': deep_result is not None,
        'similar_domain': quick_result.get('similar_domain'),
        'analysis_time': analysis_time,
        'icon': icon
    })

@app.route('/api/stats')
def get_stats():
    return jsonify(threat_db.get_stats())

@app.route('/report', methods=['POST'])
def report_url():
    data = request.get_json()
    url = data.get('url')
    if url:
        threat_db.add_threat(url, 80)
        return jsonify({'success': True})
    return jsonify({'success': False}), 400

@app.route('/')
def home():
    """Main homepage - renders the modern Glassmorphism UI"""
    return render_template('index.html')

if __name__ == '__main__':
    print("🚀 Smart API running on http://localhost:5002")
    app.run(debug=True, port=5002, threaded=True)