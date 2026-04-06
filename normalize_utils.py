# normalize_utils.py - تطبيع الروابط ومنع التكرار

from urllib.parse import urlparse, urlunparse
import hashlib
import re

def normalize_url(url):
    """
    توحيد صيغة الرابط لمنع التكرار
    - http/https موحدين إلى https
    - إزالة www
    - إزالة الـ trailing slash
    - إزالة fragments (#...)
    """
    if not url:
        return ""
    
    url = url.lower().strip()
    
    # إضافة https:// إذا لم يكن هناك بروتوكول
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    
    # توحيد البروتوكول إلى https
    scheme = 'https'
    
    # إزالة www من البداية
    netloc = parsed.netloc
    if netloc.startswith('www.'):
        netloc = netloc[4:]
    
    # إزالة trailing slash من المسار
    path = parsed.path.rstrip('/')
    if not path:
        path = ''
    
    # تجاهل fragments
    normalized = urlunparse((scheme, netloc, path, '', '', ''))
    
    return normalized

def get_url_hash(url):
    """تحويل الرابط إلى Hash فريد (للتخزين الآمن)"""
    normalized = normalize_url(url)
    return hashlib.sha256(normalized.encode()).hexdigest()

def extract_domain(url):
    """استخراج النطاق من الرابط"""
    try:
        parsed = urlparse(normalize_url(url))
        domain = parsed.netloc
        # إزالة subdomains غير الضرورية (اختياري)
        parts = domain.split('.')
        if len(parts) > 2:
            # نحتفظ بآخر جزئين فقط (example.com)
            domain = '.'.join(parts[-2:])
        return domain
    except:
        return ""

def is_suspicious_tld(domain):
    """التحقق من وجود نطاقات مشبوهة"""
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.link', '.click', '.download']
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return True
    return False