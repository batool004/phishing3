# test_phishing_urls.py - Test your model against real phishing URLs

import requests
import time

# Real phishing URLs for testing
PHISHING_URLS = [
    "https://roblox.com.ge/communities/9513516219/",
    "http://allianzhub.vercel.app/",
    "http://bet426.cc/",
    "https://rblx.foo/s/zJdqB9",
    "http://www.netflix-nine-lovat.vercel.app/",
    "https://www.robiox.com.py/users/251193591758/profile",
    "https://dpd.expressrouteflow.cfd/com/",
    "https://crackaf-bubbles-frontend.vercel.app/",
    "http://kkucoin-en-webpage.webflow.io/",
    "https://smart-autofix.pages.dev/",
]

# Safe URLs for comparison
SAFE_URLS = [
    "https://www.google.com",
    "https://www.github.com",
    "https://www.python.org",
    "https://www.wikipedia.org",
    "https://stackoverflow.com",
]

def test_phishing_urls():
    """Test API against phishing URLs"""
    
    API_URL = "http://localhost:5002/smart-check"
    
    print("=" * 60)
    print("TESTING PHISHGUARD AGAINST PHISHING URLS")
    print("=" * 60)
    print(f"API URL: {API_URL}")
    print()
    
    # First, check if API is running
    try:
        test_response = requests.get("http://localhost:5002/api/stats", timeout=2)
        print("✅ API is running!")
    except:
        print("❌ ERROR: API is not running!")
        print("   Please start the API first: python smart_api.py")
        return
    
    print("\n🔴 TESTING PHISHING URLS:")
    print("-" * 50)
    
    detected = 0
    total = 0
    results = []
    
    for url in PHISHING_URLS:
        try:
            response = requests.post(
                API_URL,
                json={"url": url},
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                is_phishing = data.get('is_phishing', False)
                score = data.get('score', 0)
                
                total += 1
                
                if is_phishing or score > 50:
                    detected += 1
                    status = "✅ DETECTED"
                    print(f"{status} | Score: {score:3.0f}% | {url[:60]}...")
                    results.append({'url': url, 'detected': True, 'score': score})
                else:
                    status = "❌ MISSED"
                    print(f"{status} | Score: {score:3.0f}% | {url[:60]}...")
                    results.append({'url': url, 'detected': False, 'score': score})
            else:
                print(f"⚠️ HTTP {response.status_code} | {url[:60]}...")
                
        except requests.exceptions.ConnectionError:
            print(f"❌ CONNECTION ERROR | {url[:60]}...")
        except Exception as e:
            print(f"❌ ERROR: {str(e)[:50]} | {url[:60]}...")
        
        time.sleep(0.1)  # Small delay
    
    print("\n🟢 TESTING SAFE URLS:")
    print("-" * 50)
    
    false_positives = 0
    safe_total = 0
    
    for url in SAFE_URLS:
        try:
            response = requests.post(
                API_URL,
                json={"url": url},
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                is_phishing = data.get('is_phishing', False)
                score = data.get('score', 0)
                
                safe_total += 1
                
                if is_phishing or score > 50:
                    false_positives += 1
                    status = "⚠️ FALSE POSITIVE"
                    print(f"{status} | Score: {score:3.0f}% | {url[:60]}...")
                else:
                    status = "✅ CORRECT (Safe)"
                    print(f"{status} | Score: {score:3.0f}% | {url[:60]}...")
                    
        except Exception as e:
            print(f"❌ ERROR | {url[:60]}...")
        
        time.sleep(0.1)
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 RESULTS SUMMARY")
    print("=" * 60)
    print(f"🔴 Phishing URLs Tested: {total}")
    print(f"   ✅ Detected: {detected}")
    print(f"   ❌ Missed: {total - detected}")
    
    if total > 0:
        detection_rate = (detected / total) * 100
        print(f"   📈 Detection Rate: {detection_rate:.1f}%")
    
    print(f"\n🟢 Safe URLs Tested: {safe_total}")
    print(f"   ✅ Correctly Classified: {safe_total - false_positives}")
    print(f"   ⚠️ False Positives: {false_positives}")
    
    if safe_total > 0:
        fp_rate = (false_positives / safe_total) * 100
        print(f"   📉 False Positive Rate: {fp_rate:.1f}%")
    
    print("\n" + "=" * 60)
    
    # Show missed URLs for improvement
    missed = [r for r in results if not r['detected']]
    if missed:
        print("\n❌ MISSED URLS (needs improvement):")
        for m in missed:
            print(f"   - {m['url'][:80]} (Score: {m['score']}%)")

if __name__ == "__main__":
    print("=" * 60)
    print("PHISHGUARD TESTER")
    print("=" * 60)
    print()
    print("Make sure your API is running on http://localhost:5002")
    print("In another terminal, run: python smart_api.py")
    print()
    input("Press Enter to start testing...")
    test_phishing_urls()