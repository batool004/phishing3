# smart_api.py - Intelligent API with background page analysis

from flask import Flask, request, jsonify
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
    """Main homepage"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>PhishGuard - Smart URL Detector</title>
        <style>
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                max-width: 900px;
                margin: 50px auto;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            .card {
                background: white;
                padding: 35px;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            h1 {
                color: #667eea;
                margin-bottom: 10px;
                font-size: 32px;
            }
            .subtitle {
                color: #666;
                margin-bottom: 30px;
                border-bottom: 1px solid #eee;
                padding-bottom: 15px;
            }
            .input-group {
                margin: 20px 0;
            }
            label {
                display: block;
                margin-bottom: 8px;
                font-weight: bold;
                color: #333;
            }
            input {
                width: 100%;
                padding: 14px;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                font-size: 16px;
                transition: all 0.3s;
                box-sizing: border-box;
            }
            input:focus {
                outline: none;
                border-color: #667eea;
            }
            button {
                width: 100%;
                padding: 14px;
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                transition: transform 0.2s;
                margin-top: 10px;
            }
            button:hover {
                transform: translateY(-2px);
            }
            .result {
                margin-top: 25px;
                padding: 20px;
                border-radius: 12px;
                display: none;
            }
            .safe {
                background: #d4edda;
                border: 1px solid #c3e6cb;
                color: #155724;
            }
            .phishing {
                background: #f8d7da;
                border: 1px solid #f5c6cb;
                color: #721c24;
            }
            .suspicious {
                background: #fff3cd;
                border: 1px solid #ffeaa7;
                color: #856404;
            }
            .result-icon {
                font-size: 48px;
                text-align: center;
                margin-bottom: 10px;
            }
            .result-title {
                font-size: 24px;
                font-weight: bold;
                text-align: center;
                margin-bottom: 15px;
            }
            .risk-factors {
                margin-top: 15px;
                padding: 12px;
                background: rgba(0,0,0,0.05);
                border-radius: 8px;
            }
            .risk-factors ul {
                margin: 10px 0 0 20px;
            }
            .risk-factors li {
                margin: 5px 0;
            }
            .stats {
                margin-top: 30px;
                padding: 20px;
                background: #f8f9fa;
                border-radius: 12px;
            }
            .stats h3 {
                margin-bottom: 15px;
                color: #333;
            }
            .stats-grid {
                display: flex;
                justify-content: space-around;
                flex-wrap: wrap;
                gap: 15px;
            }
            .stat-card {
                text-align: center;
                flex: 1;
                min-width: 100px;
            }
            .stat-number {
                font-size: 28px;
                font-weight: bold;
                color: #667eea;
            }
            .stat-label {
                font-size: 12px;
                color: #666;
                margin-top: 5px;
            }
            .loading {
                text-align: center;
                padding: 20px;
            }
            .spinner {
                border: 3px solid #f3f3f3;
                border-top: 3px solid #667eea;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 0 auto 10px;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #eee;
                font-size: 12px;
                color: #999;
            }
            @media (max-width: 600px) {
                .card { padding: 20px; }
                h1 { font-size: 24px; }
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🛡️ PhishGuard</h1>
            <div class="subtitle">AI-Powered Phishing URL Detector | Real-time Protection</div>
            
            <div class="input-group">
                <label>🔗 Enter URL to check:</label>
                <input type="text" id="urlInput" placeholder="https://example.com">
                <button onclick="checkUrl()">🔍 Analyze URL</button>
            </div>
            
            <div id="result"></div>
            
            <div class="stats">
                <h3>📊 System Statistics</h3>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number" id="totalScans">-</div>
                        <div class="stat-label">Total Scans</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="threatsFound">-</div>
                        <div class="stat-label">Threats Detected</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="successRate">-</div>
                        <div class="stat-label">Detection Rate</div>
                    </div>
                </div>
            </div>
            
            <div class="footer">
                <p>🛡️ PhishGuard | Intelligent Phishing Detection | 2026</p>
                <p style="font-size: 11px;">⚠️ For educational and security purposes only</p>
            </div>
        </div>
        
        <script>
            async function checkUrl() {
                const url = document.getElementById('urlInput').value.trim();
                const resultDiv = document.getElementById('result');
                
                if (!url) {
                    alert('Please enter a URL');
                    return;
                }
                
                resultDiv.style.display = 'block';
                resultDiv.innerHTML = '<div class="loading"><div class="spinner"></div><p>Analyzing URL...</p></div>';
                
                try {
                    const response = await fetch('/smart-check', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: url })
                    });
                    const data = await response.json();
                    
                    let resultClass = 'safe';
                    let icon = '✅';
                    let title = 'Safe URL';
                    
                    if (data.prediction === 'phishing') {
                        resultClass = 'phishing';
                        icon = '⚠️🚫';
                        title = '⚠️ Phishing Detected!';
                    } else if (data.prediction === 'suspicious') {
                        resultClass = 'suspicious';
                        icon = '⚠️';
                        title = 'Suspicious URL';
                    }
                    
                    let riskHtml = '';
                    if (data.risk_factors && data.risk_factors.length > 0) {
                        riskHtml = `
                            <div class="risk-factors">
                                <strong>⚠️ Risk Factors:</strong>
                                <ul>
                                    ${data.risk_factors.map(f => `<li>${f}</li>`).join('')}
                                </ul>
                            </div>
                        `;
                    }
                    
                    let similarHtml = '';
                    if (data.similar_domain && data.similar_domain.is_suspicious) {
                        similarHtml = `
                            <div class="risk-factors" style="margin-top: 10px;">
                                <strong>🎯 Domain Similarity Alert:</strong>
                                <ul>
                                    <li>Similar to: ${data.similar_domain.similar_to} (${data.similar_domain.similarity})</li>
                                </ul>
                            </div>
                        `;
                    }
                    
                    resultDiv.className = `result ${resultClass}`;
                    resultDiv.innerHTML = `
                        <div class="result-icon">${icon}</div>
                        <div class="result-title">${title}</div>
                        <div><strong>Threat Score:</strong> ${data.score}%</div>
                        <div style="margin-top: 10px;">${data.explanation || ''}</div>
                        <div style="margin-top: 10px;"><strong>Recommendation:</strong> ${data.recommendation}</div>
                        ${riskHtml}
                        ${similarHtml}
                        <div style="margin-top: 15px; font-size: 12px; opacity: 0.8;">
                            Analysis time: ${data.analysis_time} seconds
                            ${data.deep_analysis_performed ? ' | Deep analysis performed' : ''}
                        </div>
                    `;
                    
                    loadStats();
                    
                } catch (error) {
                    resultDiv.className = 'result phishing';
                    resultDiv.innerHTML = `
                        <div class="result-icon">❌</div>
                        <div class="result-title">Connection Error</div>
                        <div>Could not connect to server. Make sure the API is running.</div>
                        <div style="margin-top: 10px; font-size: 12px;">Error: ${error.message}</div>
                    `;
                }
            }
            
            async function loadStats() {
                try {
                    const response = await fetch('/api/stats');
                    const stats = await response.json();
                    document.getElementById('totalScans').textContent = stats.total_scans || 0;
                    document.getElementById('threatsFound').textContent = stats.total_threats || 0;
                    document.getElementById('successRate').textContent = Math.round(stats.success_rate || 0) + '%';
                } catch(e) {
                    console.log('Stats not available');
                }
            }
            
            // Support Enter key
            document.getElementById('urlInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    checkUrl();
                }
            });
            
            loadStats();
        </script>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print("🚀 Smart API running on http://localhost:5002")
    app.run(debug=True, port=5002, threaded=True)