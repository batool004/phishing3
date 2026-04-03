# intelligent_analyzer.py - Enhanced version with TF-IDF support

import difflib
import re
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import os

# List of trusted domains
TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'youtube.com', 'amazon.com',
    'microsoft.com', 'apple.com', 'paypal.com', 'github.com'
]

# Suspicious keywords
SUSPICIOUS_WORDS = [
    'login', 'verify', 'account', 'secure', 'update', 'confirm',
    'bank', 'paypal', 'signin', 'authenticate', 'validate'
]


class IntelligentAnalyzer:
    def __init__(self):
        # Load pre-trained TF-IDF model (if available)
        self.tfidf_vectorizer = None
        self.load_tfidf_model()

    def load_tfidf_model(self):
        """Load a pre-trained TF-IDF model"""
        try:
            if os.path.exists('tfidf_vectorizer.pkl'):
                self.tfidf_vectorizer = joblib.load('tfidf_vectorizer.pkl')
        except:
            pass

    def train_tfidf(self, urls):
        """Train TF-IDF model (run once)"""
        self.tfidf_vectorizer = TfidfVectorizer(max_features=20)
        self.tfidf_vectorizer.fit(urls)
        joblib.dump(self.tfidf_vectorizer, 'tfidf_vectorizer.pkl')

    def get_tfidf_features(self, url):
        """Extract TF-IDF features from a URL"""
        if self.tfidf_vectorizer:
            features = self.tfidf_vectorizer.transform([url])
            return features.toarray()[0]
        return []

    def detect_similar_domain(self, url):
        """Detect domains that mimic trusted ones"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')

        for trusted in TRUSTED_DOMAINS:
            similarity = difflib.SequenceMatcher(None, domain, trusted).ratio()
            if 0.8 < similarity < 1.0:
                return {
                    'is_suspicious': True,
                    'similar_to': trusted,
                    'similarity': f"{similarity * 100:.1f}%",
                    'warning': f"⚠️ This domain looks similar to {trusted}!"
                }
        return {'is_suspicious': False}

    def get_suspicious_score(self, url):
        """Calculate suspicion score using traditional features"""
        score = 0
        reasons = []

        # HTTPS check
        if not url.startswith('https'):
            score += 25
            reasons.append('Does not use HTTPS')

        # URL length
        if len(url) > 100:
            score += 10
            reasons.append('URL is unusually long')

        # Suspicious keywords
        for word in SUSPICIOUS_WORDS:
            if word in url.lower():
                score += 20
                reasons.append(f'Contains suspicious keyword: "{word}"')
                break

        # Domain similarity
        similar = self.detect_similar_domain(url)
        if similar['is_suspicious']:
            score += 35
            reasons.append(similar['warning'])

        return min(score, 100), reasons

    def analyze_url(self, url):
        """Full intelligent analysis (includes TF-IDF if available)"""
        # Base analysis
        suspicion_score, risk_factors = self.get_suspicious_score(url)

        # Add TF-IDF contribution if available
        tfidf_features = self.get_tfidf_features(url)
        if tfidf_features is not None and len(tfidf_features) > 0:
            tfidf_score = sum(tfidf_features) * 10
            suspicion_score = min(suspicion_score + tfidf_score, 100)

        # Classification
        if suspicion_score > 70:
            result = 'phishing'
            severity = 'critical'
            summary = '⚠️ This URL is highly dangerous! Strong phishing indicators detected.'
            recommendation = '🚫 Do NOT open this URL under any circumstances'
            needs_deep_scan = True

        elif suspicion_score > 40:
            result = 'suspicious'
            severity = 'medium'
            summary = '⚠️ This URL appears suspicious and requires deeper inspection.'
            recommendation = '⚠️ Running deep analysis...'
            needs_deep_scan = True

        else:
            result = 'safe'
            severity = 'low'
            summary = '✅ This URL appears safe'
            recommendation = '✅ Safe to open'
            needs_deep_scan = False

        return {
            'url': url,
            'score': suspicion_score,
            'result': result,
            'severity': severity,
            'summary': summary,
            'recommendation': recommendation,
            'risk_factors': risk_factors[:5],
            'needs_deep_scan': needs_deep_scan,
            'similar_domain': self.detect_similar_domain(url)
        }


# Ready-to-use analyzer instance
analyzer = IntelligentAnalyzer()