# smart_api.py - Intelligent API with background page analysis + Global Threat Network

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import joblib
import numpy as np
import time
import threading
import hashlib
from datetime import datetime
from intelligent_analyzer import analyzer
from deep_page_analyzer import deep_analyzer
from threat_db import threat_db
from normalize_utils import normalize_url, get_url_hash, extract_domain

app = Flask(__name__)
CORS(app)

# Load the main model
print("📦 Loading models...")
model = joblib.load('model.pkl')
feature_columns = joblib.load('feature_columns.pkl')
print("✅ Models ready!")

# Cache for deep scan results
deep_scan_cache = {}

# Clean up expired threats every hour (run in background)
def cleanup_expired_threats_periodically():
    """Background task to clean up expired threats"""
    while True:
        time.sleep(3600)  # Run every hour
        deleted = threat_db.cleanup_expired_threats()
        if deleted > 0:
            print(f"🧹 Cleaned up {deleted} expired threats")

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_threats_periodically, daemon=True)
cleanup_thread.start()

# ============= EXISTING ENDPOINTS =============

@app.route('/smart-check', methods=['POST'])
def smart_check():
    """Smart check with advanced analysis"""
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'Please enter a URL'}), 400
    
    start_time = time.time()
    
    # Normalize URL for consistent checking
    normalized_url = normalize_url(url)
    url_hash = get_url_hash(normalized_url)
    
    # 1. FIRST: Check global threat database (crowdsourced intelligence)
    global_threat = threat_db.get_active_threat_by_hash(url_hash)
    
    if global_threat:
        analysis_time = round(time.time() - start_time, 2)
        return jsonify({
            'url': url,
            'prediction': 'phishing',
            'is_phishing': True,
            'score': global_threat['threat_score'],
            'confidence': global_threat['threat_score'],
            'explanation': f'⚠️ This URL has been reported by {global_threat["reports_count"]} users as phishing!',
            'recommendation': '🚫 Do not open this URL - Community confirmed threat',
            'risk_factors': [f'Reported by {global_threat["reports_count"]} users', f'Trusted reports: {global_threat["trusted_reports"]}'],
            'deep_analysis_performed': False,
            'similar_domain': None,
            'analysis_time': analysis_time,
            'icon': '⚠️🚫',
            'source': 'crowdsourced'
        })
    
    # 2. Quick analysis (URL only)
    quick_result = analyzer.analyze_url(url)
    
    # 3. Check local threat database
    threat_check = threat_db.check_threat(url)
    
    # 4. If URL is suspicious, open page in background
    deep_result = None
    if quick_result['needs_deep_scan'] and url not in deep_scan_cache:
        def background_scan():
            deep_scan_cache[url] = deep_analyzer.analyze_in_background(url)
        
        thread = threading.Thread(target=background_scan)
        thread.start()
        thread.join(timeout=0.5)
        deep_result = deep_scan_cache.get(url)
    
    # 5. Merge results
    final_score = quick_result['score']
    final_risks = quick_result['risk_factors'].copy()
    
    if deep_result and deep_result.get('page_loaded'):
        final_score = max(final_score, deep_result['overall_score'])
        final_risks.extend(deep_result['suspicious_texts'][:3])
        
        if deep_result['has_login_form']:
            final_risks.append('⚠️ Page contains a login form requesting password')
        
        if deep_result['has_credit_card_form']:
            final_risks.append('⚠️ Page requests credit card information!')
    
    # 6. Determine final result
    if final_score > 40 or (threat_check and threat_check.get('is_threat')):
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
    
    # 7. Save result to database
    threat_db.add_scan(url, prediction, final_score)
    
    # 8. If phishing detected, check if it should be added to global threats
    if prediction == 'phishing' and final_score > 85:
        # This will be added when user reports it via the /report-threat endpoint
        pass
    
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
        'icon': icon,
        'source': 'ml_model'
    })

@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    stats = threat_db.get_stats()
    
    # Add global threats count
    conn = threat_db.get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM global_threats WHERE status = "confirmed"')
    global_count = cursor.fetchone()[0]
    stats['global_threats'] = global_count
    
    return jsonify(stats)

@app.route('/report', methods=['POST'])
def report_url():
    """Legacy report endpoint"""
    data = request.get_json()
    url = data.get('url')
    if url:
        threat_db.add_threat(url, 80)
        return jsonify({'success': True})
    return jsonify({'success': False}), 400

# ============= NEW: GLOBAL THREAT NETWORK ENDPOINTS =============

@app.route('/api/v2/report', methods=['POST'])
def report_threat_v2():
    """
    Report a phishing URL to the global threat network
    Anti-abuse: requires multiple reports or high ML score
    """
    data = request.get_json()
    url = data.get('url')
    user_id = data.get('user_id', 'anonymous')
    ml_score = data.get('ml_score', 0)
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    # Normalize URL
    normalized_url = normalize_url(url)
    url_hash = get_url_hash(normalized_url)
    domain = extract_domain(normalized_url)
    
    # Check if already a global threat
    existing = threat_db.get_threat_by_hash(url_hash)
    
    if existing and existing['status'] == 'confirmed':
        return jsonify({
            'status': 'already_threat',
            'message': 'This URL is already a known global threat',
            'threat_score': existing['threat_score'],
            'reports_count': existing['reports_count']
        })
    
    # Get reporter reputation
    reputation = threat_db.get_reporter_reputation(user_id)
    report_weight = 1 if reputation['reputation_score'] > 50 else 0.5
    
    if existing:
        # Increment report count
        threat_db.increment_report_count(url_hash, report_weight)
        current = threat_db.get_threat_by_hash(url_hash)
        
        # Check if should be confirmed (3 trusted reports OR 5+ reports with ML > 85)
        if current['trusted_reports'] >= 3 or (current['reports_count'] >= 5 and ml_score > 85):
            threat_db.confirm_threat(url_hash)
            return jsonify({
                'status': 'confirmed',
                'message': 'Threat confirmed! All users will now be protected.',
                'reports_count': current['reports_count'],
                'trusted_reports': current['trusted_reports'],
                'reports_needed': 0
            })
        else:
            reports_needed = max(0, 3 - current['trusted_reports'])
            return jsonify({
                'status': 'pending',
                'message': f'Threat reported. Need {reports_needed} more trusted reports to confirm.',
                'reports_count': current['reports_count'],
                'trusted_reports': current['trusted_reports'],
                'reports_needed': reports_needed
            })
    else:
        # New threat
        threat_score = max(ml_score, 70)  # Minimum 70 for reported threats
        threat_db.add_global_threat(normalized_url, url_hash, domain, threat_score, user_id, ml_score)
        
        return jsonify({
            'status': 'reported',
            'message': 'Threat reported. Waiting for confirmation from other users.',
            'reports_needed': 3,
            'threat_score': threat_score
        })

@app.route('/api/v2/check', methods=['POST'])
def check_threat_v2():
    """
    Check URL against global threat network first, then ML model
    """
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    normalized_url = normalize_url(url)
    url_hash = get_url_hash(normalized_url)
    
    # Check global threats first
    threat = threat_db.get_active_threat_by_hash(url_hash)
    
    if threat:
        return jsonify({
            'is_threat': True,
            'threat_score': threat['threat_score'],
            'reports_count': threat['reports_count'],
            'trusted_reports': threat['trusted_reports'],
            'source': 'crowdsourced',
            'message': f'⚠️ This URL has been reported by {threat["reports_count"]} users'
        })
    
    # Fall back to ML model
    result = analyzer.analyze_url(url)
    
    return jsonify({
        'is_threat': result['result'] == 'phishing',
        'threat_score': result['score'],
        'source': 'ml_model',
        'risk_factors': result['risk_factors'][:5]
    })

@app.route('/api/v2/recent-threats', methods=['GET'])
def get_recent_threats():
    """Get recent confirmed global threats"""
    limit = request.args.get('limit', 10, type=int)
    threats = threat_db.get_recent_global_threats(limit)
    return jsonify({
        'threats': threats,
        'total': len(threats)
    })

@app.route('/api/v2/reputation', methods=['GET'])
def get_reputation():
    """Get reporter reputation (for extension)"""
    user_id = request.args.get('user_id', 'anonymous')
    reputation = threat_db.get_reporter_reputation(user_id)
    return jsonify(reputation)

@app.route('/')
def home():
    """Main homepage - renders the modern Glassmorphism UI"""
    return render_template('index.html')

if __name__ == '__main__':
    print("🚀 Smart API running on http://localhost:5002")
    print("🌍 Global Threat Network is ACTIVE")
    print("   - /api/v2/report - Report phishing URLs")
    print("   - /api/v2/check - Check against global threats")
    print("   - /api/v2/recent-threats - View recent threats")
    app.run(debug=True, port=5002, threaded=True)