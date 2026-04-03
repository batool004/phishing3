"""
HTML Feature Extractor for Phishing Detection
"""

import re
from urllib.parse import urlparse
import tldextract

class HTMLFeatureExtractor:
    def __init__(self):
        self.sensitive_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 'confirm',
            'banking', 'signin', 'authenticate', 'validation', 'security',
            'password', 'credential', 'alert', 'notice'
        ]
    
    def extract_basic_features(self, url):
        """Extract 13 basic features"""
        try:
            return [
                len(url),                     # 1: url_length
                int(url.startswith("http")),  # 2: valid_url
                int("@" in url),              # 3: at_symbol
                sum(kw in url.lower() for kw in self.sensitive_keywords),  # 4: sensitive_words
                url.count("/"),               # 5: path_length
                int(url.startswith("https")), # 6: isHttps
                url.count("."),               # 7: nb_dots
                url.count("-"),               # 8: nb_hyphens
                int("and" in url.lower()),    # 9: nb_and
                int("or" in url.lower()),     # 10: nb_or
                int("www" in url.lower()),    # 11: nb_www
                int(".com" in url.lower()),   # 12: nb_com
                int("_" in url)               # 13: nb_underscore
            ]
        except Exception as e:
            print(f"Error extracting basic features: {e}")
            return None
    
    def extract_advanced_features(self, url):
        """Extract 7 advanced features (total 20)"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            return {
                'has_ip': int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))),  # 14
                'has_port': int(':' in domain and domain.count(':') == 1),  # 15
                'num_subdomains': domain.count('.'),  # 16
                'num_percent': url.count('%'),  # 17
                'num_question': url.count('?'),  # 18
                'num_equal': url.count('='),  # 19
                'domain_length': len(domain)  # 20
            }
        except:
            return {
                'has_ip': 0,
                'has_port': 0,
                'num_subdomains': 0,
                'num_percent': 0,
                'num_question': 0,
                'num_equal': 0,
                'domain_length': 0
            }
    
    def extract_features_array(self, url):
        """
        Extract ALL 20 features (13 basic + 7 advanced)
        Returns list of 20 features
        """
        basic = self.extract_basic_features(url)
        if basic is None:
            return None
        
        advanced = self.extract_advanced_features(url)
        
        # Combine: 13 basic + 7 advanced = 20 features
        all_features = basic + [
            advanced.get('has_ip', 0),
            advanced.get('has_port', 0),
            advanced.get('num_subdomains', 0),
            advanced.get('num_percent', 0),
            advanced.get('num_question', 0),
            advanced.get('num_equal', 0),
            advanced.get('domain_length', 0)
        ]
        
        # Verify we have exactly 20 features
        if len(all_features) != 20:
            print(f"Warning: Expected 20 features, got {len(all_features)}")
            # Pad or truncate to 20
            if len(all_features) < 20:
                all_features.extend([0] * (20 - len(all_features)))
            else:
                all_features = all_features[:20]
        
        return all_features
    
    def get_feature_names(self):
        """Return names of all 20 features"""
        return [
            'url_length', 'valid_url', 'at_symbol', 'sensitive_words', 'path_length',
            'isHttps', 'nb_dots', 'nb_hyphens', 'nb_and', 'nb_or', 'nb_www',
            'nb_com', 'nb_underscore', 'has_ip', 'has_port', 'num_subdomains',
            'num_percent', 'num_question', 'num_equal', 'domain_length'
        ]
    
    def get_feature_count(self):
        """Return total number of features"""
        return 20
    
    def test_features(self, url):
        """Test function to verify feature extraction"""
        features = self.extract_features_array(url)
        if features:
            print(f"URL: {url}")
            print(f"Features count: {len(features)}")
            print(f"Features: {features}")
            return features
        return None